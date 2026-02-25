<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Form + Upload + Body limit test</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; }
        h1 { font-size: 1.35rem; }
        h2 { font-size: 1.1rem; margin-top: 1.5rem; color: #333; }
        label { display: block; margin-top: 0.75rem; font-weight: 500; }
        input[type="text"], input[type="number"], textarea { width: 100%; padding: 0.5rem; margin-top: 0.25rem; box-sizing: border-box; }
        textarea { min-height: 80px; resize: vertical; }
        .hint { font-size: 0.875rem; color: #666; margin-top: 0.25rem; }
        button { margin-top: 1rem; padding: 0.5rem 1rem; cursor: pointer; }
        .section { margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid #eee; }
        .inline { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
        .inline label { margin-top: 0; }
        .inline input { width: auto; }
    </style>
</head>
<body>
    <h1>Form + Upload + Body limit test</h1>
    <p>Submit form data, file (model), and/or large body to test Wafio (including body limit).</p>

    <form method="post" action="/form" enctype="multipart/form-data" id="mainForm">
        @csrf
        <div class="section">
            <h2>Form data</h2>
            <label>Title <input type="text" name="title" value="Example title" /></label>
            <label>Comment <textarea name="comment" rows="3">Enter your comment here.</textarea></label>
        </div>

        <div class="section">
            <h2>Upload file (model)</h2>
            <label>File (model / any file) <input type="file" name="model" accept="*" /></label>
            <p class="hint">Select a file to upload; field name: <code>model</code>. Files are returned as metadata in JSON response.</p>
        </div>

        <div class="section">
            <h2>Test body limit</h2>
            <p class="hint">Generate a large payload to test body size limit. Additional content will be added to the <code>body_test</code> field.</p>
            <div class="inline">
                <label>Target size (KB) <input type="number" name="body_size_kb" id="bodySizeKb" value="100" min="1" max="10240" /></label>
                <button type="button" id="btnFill">Generate &amp; fill</button>
            </div>
            <label>Additional payload (body_test) <textarea name="body_test" id="bodyTest" placeholder="Leave empty or Generate/fill to test body limit. Can also paste XSS/SQLi payload to test blocking."></textarea></label>
            <p class="hint">After clicking Generate, the field above will be filled with text of ~N KB. Submit the form to send to the server (and Wafio).</p>
        </div>

        <button type="submit">Submit form</button>
    </form>

    <script>
        (function() {
            var btn = document.getElementById('btnFill');
            var sizeKb = document.getElementById('bodySizeKb');
            var bodyTest = document.getElementById('bodyTest');
            if (!btn || !bodyTest || !sizeKb) return;
            btn.addEventListener('click', function() {
                var kb = parseInt(sizeKb.value, 10) || 100;
                if (kb < 1) kb = 1;
                if (kb > 10240) kb = 10240;
                var targetLen = kb * 1024;
                var chunk = 'x'.repeat(1024);
                var s = '';
                while (s.length < targetLen) s += chunk;
                bodyTest.value = s.slice(0, targetLen);
                bodyTest.placeholder = 'Generated ' + (bodyTest.value.length / 1024).toFixed(1) + ' KB. Submit to test.';
            });
        })();
    </script>
</body>
</html>
