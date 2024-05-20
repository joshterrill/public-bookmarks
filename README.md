# Public Bookmarks [WIP]

A REST API for publicly publishing and viewing your bookmarks.

### Registration
```bash
curl --request POST 'http://localhost:8000/register'
# {"user_id":"664ae32a9cfcc7a67c315ae0", "api_key":"563ea80f61a94026826fdf280c883bce"}
```

### Upload bookmarks (Chrome)

**One-time push**

```bash
curl 'http://localhost:8000/bookmarks/664ae32a9cfcc7a67c315ae0' \
--header 'Authorization: 563ea80f61a94026826fdf280c883bce' \
--form 'file=@"/Users/joshterrill/Library/Application Support/Google/Chrome/Default/Bookmarks"'
```

**Cronjob**

```bash
crontab -e
# update bookmarks every 8 hours
0 */8 * * * curl 'http://localhost:8000/bookmarks/664ae32a9cfcc7a67c315ae0' --header 'Authorization: 563ea80f61a94026826fdf280c883bce' --form 'file=@"/Users/joshterrill/Library/Application Support/Google/Chrome/Default/Bookmarks"' && echo "Updated bookmarks"
```

### Get bookmarks

```bash
curl 'http://localhost:8000/bookmarks/664ae32a9cfcc7a67c315ae0'
```

### Todo
* Define bookmark folders to sync as part of user registration
* Add upsert calls on `Bookmarks` collection

### License
MIT