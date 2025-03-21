This is my tables from my database. Press view in code to view better.

mysql> DESC logs;
+---------------+--------------+------+-----+---------+----------------+
| Field         | Type         | Null | Key | Default | Extra          |
+---------------+--------------+------+-----+---------+----------------+
| id            | int          | NO   | PRI | NULL    | auto_increment |
| timestamp     | datetime     | NO   |     | NULL    |                |
| client_ip     | varchar(45)  | NO   |     | NULL    |                |
| status_code   | varchar(255) | YES  |     | NULL    |                |
| method        | varchar(10)  | NO   |     | NULL    |                |
| url           | text         | NO   |     | NULL    |                |
| message       | text         | YES  |     | NULL    |                |
| process_time  | int          | YES  |     | NULL    |                |
| full_log_line | text         | YES  |     | NULL    |                |
+---------------+--------------+------+-----+---------+----------------+
9 rows in set (0.10 sec)

mysql> DESC alerts;
+-------------+----------------------------------------+------+-----+-------------------+-------------------+
| Field       | Type                                   | Null | Key | Default           | Extra             |
+-------------+----------------------------------------+------+-----+-------------------+-------------------+
| id          | int                                    | NO   | PRI | NULL              | auto_increment    |
| timestamp   | datetime                               | YES  |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED |
| client_ip   | varchar(45)                            | YES  |     | NULL              |                   |
| method      | varchar(10)                            | YES  |     | NULL              |                   |
| url         | text                                   | YES  |     | NULL              |                   |
| message     | text                                   | YES  |     | NULL              |                   |
| severity    | enum('Low','Medium','High','Critical') | NO   |     | NULL              |                   |
| assigned_to | varchar(50)                            | YES  |     | Unassigned        |                   |
| status      | enum('Open','Acknowledged','Resolved') | NO   |     | NULL              |                   |
| visit_count | int                                    | YES  |     | 1                 |                   |
+-------------+----------------------------------------+------+-----+-------------------+-------------------+
10 rows in set (0.05 sec)


mysql> DESC cases;
+--------------+----------------------------------------+------+-----+-------------------+-------------------+
| Field        | Type                                   | Null | Key | Default           | Extra             |
+--------------+----------------------------------------+------+-----+-------------------+-------------------+
| id           | int                                    | NO   | PRI | NULL              | auto_increment    |
| timestamp    | datetime                               | YES  |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED |
| client_ip    | varchar(45)                            | YES  |     | NULL              |                   |
| status_code  | varchar(255)                           | YES  |     | NULL              |                   |
| method       | varchar(10)                            | YES  |     | NULL              |                   |
| url          | text                                   | YES  |     | NULL              |                   |
| severity     | enum('Low','Medium','High','Critical') | YES  |     | NULL              |                   |
| assigned_to  | varchar(100)                           | YES  |     | NULL              |                   |
| message      | text                                   | YES  |     | NULL              |                   |
| status       | enum('In Progress','Closed')           | NO   |     | In Progress       |                   |
| alert_id     | int                                    | YES  | MUL | NULL              |                   |
| case_details | text                                   | YES  |     | NULL              |                   |
+--------------+----------------------------------------+------+-----+-------------------+-------------------+
12 rows in set (0.02 sec)
