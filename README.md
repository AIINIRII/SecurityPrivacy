# Security Privacy

## Instruction

### Run after compiling

1. download the source code
2. modify the "downloadFilePath" property in the file src/main/resources/application.yml
3. use maven to compile the project and run the project

### Run using compiled jar package

1. use `java -jar ./release/securityprivacy-main-0.0.1-SNAPSHOT.jar` to run the project

*Warn! Due to you didn't set the 'downloadFilePath', it will be set as a default value ".\\cache\\"*