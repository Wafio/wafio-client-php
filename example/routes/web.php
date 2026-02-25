<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/form', function () {
    return view('form');
});

Route::post('/form', function (Request $request) {
    $files = [];
    if ($request->hasFile('model')) {
        $fileInputs = $request->file('model');
        $fileList = is_array($fileInputs) ? $fileInputs : [$fileInputs];
        foreach ($fileList as $file) {
            if ($file !== null) {
                $files[] = [
                    'field' => 'model',
                    'name' => $file->getClientOriginalName(),
                    'mimetype' => $file->getClientMimeType(),
                    'size' => $file->getSize(),
                ];
            }
        }
    }

    $bodyTest = (string) $request->input('body_test', '');

    return response()->json([
        'message' => 'Form received',
        'fields' => [
            'title' => $request->input('title'),
            'comment' => $request->input('comment'),
            'body_test_length' => strlen($bodyTest),
            'body_test_preview' => strlen($bodyTest) > 100 ? substr($bodyTest, 0, 100) . '…' : $bodyTest,
        ],
        'files' => $files,
        'upload_note' => 'Files are processed and returned as metadata only (not persisted to disk)',
        'raw_body_length' => strlen((string) $request->getContent()),
    ]);
});

Route::get('/safe', function () {
    return response()->json(['message' => 'Safe response']);
});

Route::get('/search', function (Request $request) {
    $q = $request->query('q', '');
    return response()->json(['query' => $q, 'results' => []]);
});

Route::get('/page', function (Request $request) {
    $name = $request->query('name', '');
    return response()->json(['name' => $name]);
});

Route::post('/comment', function (Request $request) {
    $comment = $request->input('comment', $request->all());
    return response()->json(['received' => $comment]);
});
