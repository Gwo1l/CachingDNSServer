Это кэширующий DNS сервер. Он ожидает и принимает запросы от клиентов через сетевой сокет. Полученные данные анализируются как DNS-запрос с использованием метода DNSRecord.parse. 
Проверка наличия запрошенной информации в локальном кэше: Если запрашиваемая запись присутствует в кэше и соответствует запрошенному типу запроса, сервер отправит ответ клиенту на основе данных из кэша. 
Если запись не найдена в кэше, сервер использует рекурсивные запросы DNS, отправляя запросы на различные DNS-сервера для поиска и получения запрошенной информации о домене.
Обновление кэша с полученными записями для будущего использования.
После получения информации о запрошенном домене, сервер формирует ответ и отправляет его обратно клиенту.

Тесты:

![image](https://github.com/Gwo1l/CachingDNSServer/assets/146204894/8642f83d-01d7-49fb-b08f-1758b1b91488)
![image](https://github.com/Gwo1l/CachingDNSServer/assets/146204894/acebbe84-3923-4066-8279-852eaa5f0e25)



Ахямов Р. кн-202
