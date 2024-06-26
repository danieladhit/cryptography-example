## PREREQUISITE

There are 2 encryption on this example
- Encrypt/Decrypt key: using RSA OAEP 256 encryption
- Encrypt/Decrypt payload: using AES GCM encryption

### Generate RSA Key Pair
Create a `key` directory int root folder
    
    mkdir key
    cd key
#### Note: if using OpenSSL 3.0, can use the -traditional switch to get the older format for output, both for the openssl genrsa and openssl rsa subcommands. 
Generate 2048 bit RSA Key

    openssl genrsa -des3 -out private.pem 2048
Export the RSA Private Key

    openssl rsa -in private.pem -out priv.pem -outform PEM
Export the RSA Public Key

    openssl rsa -in private.pem -outform PEM -pubout -out pub.pem
Remove the RSA Key

    rm private.pem


## HOW TO RUN
### GO
``` bash
cd go-example
go run ./main.go
```
### PHP 
``` bash
cd php-example
composer install 
php main.php  
```
### JAVA
```bash
cd java-example
mvn install
mvn exec:java -Dexec.mainClass="com.java.example.Example"
```
### C# 
``` bash
cd c\#-example
dotnet run 
```

### JS
``` bash
cd js-example
npm install crypto --save 
```

### Python
``` bash
cd python-example
pip install -r requirements.txt
python main.py
```
