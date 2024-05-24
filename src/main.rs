use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use chrono::Utc;
use dotenv::dotenv;
use futures_util::stream::TryStreamExt;
use futures_util::StreamExt;
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use mongodb::options::FindOneAndUpdateOptions;
use mongodb::{options::ClientOptions, options::FindOptions, Client, Collection, Database};
use serde::{Deserialize, Serialize};
use sha256::digest as Sha256;
use std::env;
use std::str::FromStr;
use uuid::Uuid;
use anyhow::{Context, Result};
use mongodb::bson::Bson;

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Bookmark {
    date_added: Option<String>,
    date_last_used: Option<String>,
    guid: Option<String>,
    id: Option<String>,
    meta_info: Option<MetaInfo>,
    name: Option<String>,
    #[serde(rename = "type")]
    bookmark_type: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct MetaInfo {
    power_bookmark_meta: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct BookmarkFile {
    roots: Roots,
}

#[derive(Debug, Deserialize, Serialize)]
struct Roots {
    bookmark_bar: BookmarkBar,
}

#[derive(Debug, Deserialize, Serialize)]
struct BookmarkBar {
    children: Vec<BookmarkNode>,
}

#[derive(Debug, Deserialize, Serialize)]
struct BookmarkNode {
    name: String,
    #[serde(default)]
    children: Vec<Bookmark>,
    #[serde(flatten)]
    bookmark: Option<Bookmark>,
    url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct BookmarkDocument {
    user_id: String,
    bookmarks: Vec<Bookmark>,
    created_at: String,
    previous_last_bookmark_url: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct UserDocument {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    api_key: String,
    created_at: String,
    folders: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct UserRegisterRequest {
    folders: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct UserRegisterResponse {
    user_id: String,
    api_key: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

async fn register_user(
    user_register_req: web::Json<UserRegisterRequest>,
    db: web::Data<Collection<UserDocument>>,
) -> Result<HttpResponse, actix_web::Error> {
    let api_key = Uuid::new_v4().simple().to_string();
    let created_at = Utc::now().to_rfc3339();
    let hashed_api_key = Sha256(&api_key);

    let user_doc = UserDocument {
        id: None,
        api_key: hashed_api_key,
        created_at: created_at.clone(),
        folders: user_register_req.folders.clone(),
    };

    let collection = db.as_ref();
    let inserted = collection
        .insert_one(user_doc.clone(), None)
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Failed to insert into database: {}",
                e
            ))
        })?;

    let user_obj_id = inserted.inserted_id
        .as_object_id()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Failed to get inserted ID"))?;

    let user_res = UserRegisterResponse {
        user_id: user_obj_id.to_hex(),
        api_key: api_key,
    };

    Ok(HttpResponse::Created().json(user_res))
}

async fn get_bookmarks_by_user(
    user_id: web::Path<String>,
    db: web::Data<Collection<BookmarkDocument>>,
) -> Result<HttpResponse, actix_web::Error> {
    let filter = doc! { "user_id": user_id.to_owned() };
    let find_options = FindOptions::builder()
        .sort(doc! { "created_at": -1 })
        .limit(1)
        .build();

    let collection = db.as_ref();
    let mut cursor = collection.find(filter, find_options).await.map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Failed to execute find: {}", e))
    })?;

    if let Some(result) = cursor.try_next().await.map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Failed to fetch result: {}", e))
    })? {
        Ok(HttpResponse::Ok().json(result))
    } else {
        Ok(HttpResponse::NotFound().json(ErrorResponse {
            error: "No bookmarks found".to_string(),
        }))
    }
}

async fn save_bookmarks(
    user_id: web::Path<String>,
    upload: actix_multipart::Multipart,
    db: web::Data<Collection<BookmarkDocument>>,
    user_db: web::Data<Collection<UserDocument>>,
    req: HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id_str = user_id.clone();

    let auth_header = req
        .headers()
        .get("Authorization")
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authorization header missing"))?;

    let api_key = auth_header
        .to_str()
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid Authorization header format"))?;

    let hashed_api_key = Sha256(api_key);

    let user_obj_id = ObjectId::from_str(&user_id).map_err(|_| {
        actix_web::error::ErrorBadRequest("Invalid user ID format")
    })?;    

    let user_filter = doc! {
        "_id": user_obj_id,
        "api_key": &hashed_api_key,
    };

    let user_collection = user_db.as_ref();
    let user = user_collection
        .find_one(user_filter, None)
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to query database: {}", e))
        })?;

    if user.is_none() {
        return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid API key or user ID".to_string(),
        }));
    }

    let mut file_content = Vec::new();
    let mut upload = upload;
    let mut field = upload
        .next()
        .await
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Failed to read file content"))??;

    while let Some(chunk) = field.try_next().await.map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Failed to read file content: {}", e))
    })? {
        file_content.extend_from_slice(&chunk);
    }

    let contents = String::from_utf8(file_content).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!(
            "Failed to convert file content to string: {}",
            e
        ))
    })?;
    let bookmark_file: BookmarkFile = serde_json::from_str(&contents)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Failed to parse JSON: {}", e)))?;

    let mut read_later_bookmarks = Vec::new();
    
    let doc_user = user.unwrap();
    
    for child in &bookmark_file.roots.bookmark_bar.children {
        if doc_user.folders.contains(&child.name) {
            collect_bookmarks(&child.children, &mut read_later_bookmarks);
        }
    }
    let collection = db.as_ref();
    let get_existing_bookmar_by_user = collection
        .find_one(doc! { "user_id": user_id_str.to_owned() }, None)
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Failed to query database: {}",
                e
            ))
        })?;
    let mut previous_last_bookmark_url: String = get_existing_bookmar_by_user.unwrap_or(read_later_bookmarks.clone().last().map(|b| b.url.clone()).flatten().unwrap_or_default("".to_owned()));
    // let last_bookmark_url = read_later_bookmarks.last().map(|b| b.url.clone()).flatten().unwrap_or_default();

    let bookmark_doc = BookmarkDocument {
        user_id: user_id_str.to_owned(),
        bookmarks: read_later_bookmarks,
        created_at: Utc::now().to_rfc3339(),
        last_indexed_url: last_bookmark_url,
    };
    impl Into<Bson> for Bookmark {
        fn into(self) -> Bson {
            Bson::Document(doc! {
                "name": self.name,
                "url": self.url,
                "bookmark_type": self.bookmark_type,
            })
        }
    }

    impl Into<Bson> for BookmarkDocument {
        fn into(self) -> Bson {
            Bson::Document(doc! {
                "user_id": self.user_id,
                "bookmarks": self.bookmarks.into_iter().map(|b| b.into()).collect::<Vec<Bson>>(),
                "created_at": self.created_at,
                "last_indexed_url": self.last_indexed_url,
            })
        }
    }

    let insert_options = FindOneAndUpdateOptions::builder()
        .upsert(Some(true))
        .build();
    collection
        .find_one_and_update(doc! { "user_id": user_id_str.to_owned() }, doc! { "$set": bookmark_doc.to_owned() }, Some(insert_options))
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Failed to insert into database: {}",
                e
            ))
        })?;

    Ok(HttpResponse::Accepted().json(bookmark_doc.to_owned()))
}

fn collect_bookmarks(nodes: &[Bookmark], bookmarks: &mut Vec<Bookmark>) {
    for node in nodes {
        if node.bookmark_type.as_deref() != Some("folder") {
            bookmarks.push(node.clone());
        }
    }
}

async fn init_db() -> Result<Database> {
    let db_user = env::var("MONGODB_USER").context("MONGODB_USER not set")?;
    let db_password = env::var("MONGODB_PASSWORD").context("MONGODB_PASSWORD not set")?;
    let db_host = env::var("MONGODB_HOST").context("MONGODB_HOST not set")?; // i.e. "public-bookmarks.abcde.mongodb.net"
    let db_connection_url = format!(
        "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority",
        db_user, db_password, db_host
    );
    let client_options = ClientOptions::parse(db_connection_url).await.context("Failed to parse mongodb connection url")?;
    let client = Client::with_options(client_options).context("Failed to create mongodb client")?;
    Ok(client.database("public-bookmarks"))
}

#[actix_web::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let ip_bind = env::var("IP_BIND").unwrap_or_else(|_| "localhost".to_owned());
    let port = env::var("PORT").unwrap_or_else(|_| "8000".to_owned());
    let db = init_db().await?;
    let user_collection: Collection<UserDocument> = db.collection("Users");
    let bookmark_collection: Collection<BookmarkDocument> = db.collection("Bookmarks");

    println!("Starting server at http://{}:{}", ip_bind, port); 

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(user_collection.clone()))
            .app_data(web::Data::new(bookmark_collection.clone()))
            .route("/", web::get().to(hello))
            .route("/register", web::post().to(register_user))
            .route("/bookmarks/{user_id}", web::get().to(get_bookmarks_by_user))
            .route("/bookmarks/{user_id}", web::post().to(save_bookmarks))
    })
    .bind((ip_bind, port.parse::<u16>().expect("Invalid port number")))?
    .run()
    .await
    .context("Failed to start http server")?;

    Ok(())
}
