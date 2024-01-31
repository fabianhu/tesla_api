<?php
// Get all parameters from the URL
$params = $_GET;

// Open a file for writing (create if not exists)
$file = fopen('parameters.txt', 'a');

// Write each parameter and its value to the file
foreach ($params as $key => $value) {
    fwrite($file, $key . ': ' . $value . PHP_EOL);
}

// Close the file
fclose($file);

echo 'Parameters saved to file.';

// Print each parameter and its value
foreach ($params as $key => $value) {
    echo $key . ': ' . $value . '<br>';
}
?>
