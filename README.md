## To obtain JWT

`curl --location --request POST 'http://localhost:8085/oauth/token' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'username=admin@TEST01.com' \
--data-urlencode 'password=password'`