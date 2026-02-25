<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Wafio sample</title>
</head>
<body>
    <h1>Wafio Laravel sample</h1>
    <p>Every request is checked by Wafio. Try:</p>
    <ul>
        <li><a href="/safe">Safe page</a></li>
        <li><a href="/form">Form + upload + body limit test</a></li>
        <li><a href="/search?q=hello">Search (safe)</a></li>
        <li><a href="/search?q=1' OR '1'='1">Search (SQLi - may be blocked)</a></li>
        <li><a href="/page?name=%3Cscript%3Ealert(1)%3C/script%3E">XSS in query</a></li>
    </ul>

    <form method="post" action="/comment">
        @csrf
        <label>Comment: <input name="comment" value="Normal text" /></label>
        <button type="submit">Submit</button>
    </form>

    <p>Or POST a request body with XSS/SQLi payload to test blocking.</p>
</body>
</html>
