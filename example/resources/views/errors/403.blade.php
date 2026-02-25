<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>403 Forbidden</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 560px; margin: 2rem auto; padding: 0 1rem; }
        .code { font-size: 3rem; font-weight: 700; color: #999; }
        h1 { color: #c00; font-size: 1.5rem; }
        p { color: #333; line-height: 1.5; }
        .categories { margin-top: 1rem; }
    </style>
</head>
<body>
    <p class="code">403</p>
    <h1>Forbidden</h1>
    <p>{{ $message }}</p>
    @if(!empty($categories))
        <p class="categories">Categories: {{ implode(', ', $categories) }}</p>
    @endif
</body>
</html>
