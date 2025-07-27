```shell
./crypto_app.exe encrypt model.onnx encrypted.bin 12345678901234567890123456789012 aes-256-gcm
./crypto_app.exe decrypt encrypted.bin de.onnx 12345678901234567890123456789012 aes-256-gcm

./crypto_app.exe encrypt model.onnx encrypted.bin 12345678901234567890123456789012 aes-256-cbc
./crypto_app.exe decrypt encrypted.bin de.onnx 12345678901234567890123456789012 aes-256-cbc
```