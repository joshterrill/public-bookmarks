use std::env;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use chrono::Utc;
use futures_util::stream::TryStreamExt;
use futures_util::StreamExt;
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use mongodb::{options::ClientOptions, options::FindOptions, Client, Collection, Database};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

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
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct UserDocument {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    api_key: String,
    created_at: String,
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
    db: web::Data<Arc<Collection<UserDocument>>>,
) -> Result<HttpResponse, actix_web::Error> {
    let api_key = Uuid::new_v4().simple().to_string();
    let created_at = Utc::now().to_rfc3339();
    let mut hasher = Sha256::new();
    hasher.update(api_key.clone());
    let hashed_api_key = format!("{:x}", hasher.finalize());

    let user_doc = UserDocument {
        id: None,
        api_key: hashed_api_key,
        created_at: created_at.clone(),
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

    let user_res = UserRegisterResponse {
        user_id: inserted.inserted_id.as_object_id().unwrap().to_hex(),
        api_key: api_key,
    };

    Ok(HttpResponse::Created().json(user_res))
}

async fn get_bookmarks_by_user(
    user_id: web::Path<String>,
    db: web::Data<Arc<Collection<BookmarkDocument>>>,
) -> Result<HttpResponse, actix_web::Error> {
    let filter = doc! { "user_id": &user_id.into_inner() };
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
    db: web::Data<Arc<Collection<BookmarkDocument>>>,
    user_db: web::Data<Arc<Collection<UserDocument>>>,
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

    let mut hasher = Sha256::new();
    hasher.update(api_key);
    let hashed_api_key = format!("{:x}", hasher.finalize());

    let user_filter = doc! {
        "_id": ObjectId::from_str(&user_id).unwrap(),
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
    for child in &bookmark_file.roots.bookmark_bar.children {
        if child.name == "read later" {
            collect_bookmarks(&child.children, &mut read_later_bookmarks);
        }
    }

    let bookmark_doc = BookmarkDocument {
        user_id: user_id_str,
        bookmarks: read_later_bookmarks,
        created_at: Utc::now().to_rfc3339(),
    };

    let collection = db.as_ref();
    collection
        .insert_one(bookmark_doc.clone(), None)
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Failed to insert into database: {}",
                e
            ))
        })?;

    Ok(HttpResponse::Accepted().json(bookmark_doc))
}

fn collect_bookmarks(nodes: &[Bookmark], bookmarks: &mut Vec<Bookmark>) {
    for node in nodes {
        if node.bookmark_type.as_deref() != Some("folder") {
            bookmarks.push(node.clone());
        }
    }
}

async fn init_db() -> Database {
    let db_user = env::var("MONGODB_USER").unwrap(); // this will never panic
    let db_password = env::var("MONGODB_PASSWORD").unwrap();
    let db_host = env::var("MONGODB_HOST").unwrap(); // i.e. "public-bookmarks.abcde.mongodb.net"
    let db_connection_url = format!(
        "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority",
        db_user, db_password, db_host
    );
    let client_options = ClientOptions::parse(db_connection_url).await.unwrap();
    let client = Client::with_options(client_options).unwrap();
    client.database("public-bookmarks")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let db = init_db().await;
    let user_collection: Collection<UserDocument> = db.collection("Users");
    let bookmark_collection: Collection<BookmarkDocument> = db.collection("Bookmarks");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(Arc::new(user_collection.clone())))
            .app_data(web::Data::new(Arc::new(bookmark_collection.clone())))
            .route("/", web::get().to(hello))
            .route("/register", web::post().to(register_user))
            .route("/bookmarks/{user_id}", web::get().to(get_bookmarks_by_user))
            .route("/bookmarks/{user_id}", web::post().to(save_bookmarks))
    })
    .bind(("127.0.0.1", 8000))?
    .run()
    .await
}
