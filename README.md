# GoJWT

## Api:

* HttpGet: `http://<address>:<port>/login?userId=<value>` (Получение пары токенов 'Access' и 'Refresh')

    Example: `http://193.123.36.213:5010/login?userId=user1`


* HttpPost: `http://<address>:<port>/refresh` (Обновление токенов)

  Example: `http://193.123.36.213:5010/refresh` 


* HttpGet: `http://<address>:<port>/home` (Получение данных после авторизации)

    Example: `http://193.123.36.213:5010/home` 


* HttpGet: `http://<address>:<port>/clear` (Сброс токенов)

    Example: `http://193.123.36.213:5010/clear` 

