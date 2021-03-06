--------------------------------POS Test Server--------------------------------
POS Test Server - тестовое серверное приложение, предназначеное для проведения
		  операций, связанных с ПОС-терминалами. 
 
[1] Подготовка к запуску

- Создайте коннект в системе ТМС SPRUT с IPv4 компьютера, на котором будет за-
  пущен сервер, порт можно выбрать любой, но рекомендуется использовать 12345, 
  так сервер не придется перезапускать при первом включении, так как этот порт 
  используется по умолчанию.

- В профиле (в ТМС SPRUT) необходимо выставить созданный коннект в необходимый
  экваер.

- После сохранения всех настроек проинициализируйте терминал на нужный профиль.

[2] Запуск сервера

- Запустите исполняемый файл server.exe.

- При запуске сервер создаст все необходимые файлы и начнет работу, если не 
  возникнет ошибок, связанных с использованием выбранного ip/port другой 
  программой. Файлы, который создает сервер для корректной работы:
	- src/clue.txt - подсказка пользователю, помогает быстро определить
	тип проводимой операции.
	- src/config.ini - настроечный файл, определяет какие поля будут гене-
	рироваться при формировании ответа. Формат:
		
[Transaction code]
{Message type}-{Message sub type}=A;B;C;...|(поле с подполями)[a,b,c,..]

	Если берется поле с подполями, убедитесь, что само поле указано в бло-
	ке с полями, иначе оно будет игнорироваться.
	- src/data.db - база данных, в которой хранится история операций и
	виртуальные счета, которые заводятся на определенный Card acceptor 
	terminal.
	- src/srv_settings.ini - настроечный файл сервера с его конфигурацией 
	и кодами ответа для режима "эмулятора".

[3] Использование

- Сервер запущен и готов к использовнию, при правильных настройках профиля 
  запросы с терминала должны идти на сервер.	

- Если целостность сервера будет нарушена, достаточно удалить всю папку "src",
  и уже при повторном запуске сервера все файлы восстановятся с настройками
  по умолчанию. Также можно удалять по одному поврежденному файлу, при запуске 
  сервер делает обход директории на проверку целостности.

- Если сервер не отвечает на запрос и пишет в консоль:

    >>Operation is not supplied.

  В этом случае нужно открыть src/config.ini и заполнить соответсвуююшее
  общей форме поле. Если сервер работает в режиме эмулятора, то нужно еще запо-
  лнить соответсвующие поля RC в файле src/srv_settings.ini

- Если сервер пишет в консоль:

    >>Terminal id = "[Terminal_ID]" is not present in database

  Для того, чтобы этого не было, нужно открыть src/data.db через SQLiteStudio
  и зайти в таблицу acquirer_data, там нужно создать новую строку и заполнить
  необходимые поля, а именно:
        - card_acceptor_terminal = необходимо взять значение из ТМС
        - amount = сумма, которую вы хотите на счет
        - preauth_amount = 0

- В случае, когда нужно выстаивть время игнорирования операции, нужно открыть 
  src/data.db через SQLiteStudio и зайти в таблицу tptp_ignore_list, в колонке
  'value' нужно выставить необходимое время (в секундах) напротив нужной опера-
  ции. Если нужно выстаивть одно время для всех операций, тогда нужно выставить
  значение в колонке напротив 'GENERAL'.
--------------------------------POS Test Server--------------------------------

v0.0.0 - альфа-версия, поддерживается только работа по протоколу TPTP, только
	в режиме "эмулятора", количество генерируемых полей сильно ограничено.	

v0.0.1 - бета-версия, добавлен режим полноценного сервера.

v0.0.2 - добавлены операции: сверка, загрузка ключей, тест связи.

v0.0.3 - добавлена возможность выставить время игнрирования хостом операции.

v0.0.4 - добавлены финансовые операции для протокола OWN в режиме эмулятора.

v0.0.5 - добавлена операция "загрузка ключей" для протокола OWN.

v0.0.6 - добавлено МАС-шифрование и поддержка протокола Secure ISO.