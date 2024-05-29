# Public Bookmarks [WIP]

https://bookmarks.dangerous.dev/

A REST API for publicly publishing and viewing your bookmarks.

### Requirements

* MongoDB

### Installation

1. Run `cp .env.examples .env`
2. Replace environment variables placeholders with real values
3. Run `cargo build --release`
4. And run binary at `target/release/public-bookmarks`

### Registration
```bash
curl --location 'http://localhost:8000/register' \
--header 'Content-type: application/json' \
--data '{
    "folders": ["read later"]
}'
# {"user_id":"664ae32a9cfcc7a67c315ae0", "api_key":"563ea80f61a94026826fdf280c883bce"}
```

**If no folders are provided, it will take all bookmarks**


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
* Create Github action to build releasees for all targets based on pushes to master
* Add support for other browsers such as Edge, Firefox, Safari

### License
MIT
