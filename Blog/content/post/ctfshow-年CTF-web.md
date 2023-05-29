---
title: "ctfshow-年CTF-web"
date: 2023-05-29T13:22:26+08:00
categories: ["ctfshow"]
---

# ctfshow-年CTF-web

##  除夕

```php
Notice: Undefined index: year in /var/www/html/index.php on line 16
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2023-01-18 11:36:09
# @Last Modified by:   h1xa
# @Last Modified time: 2023-01-19 10:18:44
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/

include "flag.php";

$year = $_GET['year'];

if($year==2022 && $year+1!==2023){
    echo $flag;
}else{
    highlight_file(__FILE__);
}
```

#### 题目分析

```php
$year==2022 && $year+1!==2023
```

第一个弱比较，第二个强比较，

尝试了2022a,第一个if可以，第二个if绕不过，因为会转换为整数2022

尝试了2022.9，第一个if不可以，第二个if可以成功绕过，2022.9 是一个浮点数，而 2022 是一个整数。虽然它们的值看起来很接近，但由于浮点数的精度限制，它们可能不会被判断为相等。

尝试了2022e2，由于浮点数 2022e2 表示的数值为 202200，与整数 2022 不相等。

#### 知识点

##### 在 PHP 中，科学计数法表示的数字会被解释为浮点数类型。

#### payload（浮点数类型绕过）

```
?year=2022.0

当比较 $year == 2022 时，由于进行了类型转换，字符串 "2022.0" 会被转换为整数 2022。因此，条件 $year == 2022 返回 true。
另外，$year + 1 !== 2023 的比较中使用了不等于（!==）操作符，该操作符会同时比较值和类型。由于 $year + 1 的结果是浮点数 2023.0，而不是整数 2023，因此条件 $year + 1 !== 2023 返回 true。
```

```
?year=202.2e1
 $year 被赋值为科学计数法表示的浮点数 "202.2e1"。202.2e1 表示 202.2 乘以 10 的 1 次方，即 2022.0。
```

```
?year=2022.a

在这种情况下，字符串 "2022.a" 中的开头部分 "2022" 是一个有效的数字，因此 PHP 将其转换为数字类型。由于存在小数点之后的字符 "a"，PHP 将其忽略并将字符串转换为浮点数类型。
因此，"2022.a" 被转换为浮点数 2022.0，而不是整数类型。
```

## 初三

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2023-01-19 10:31:36
# @Last Modified by:   h1xa
# @Last Modified time: 2023-01-19 13:11:08
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/

error_reporting(0);
extract($_GET);
include "flag.php";
highlight_file(__FILE__);


$_=function($__,$___){
    return $__==$___?$___:$__;
};
$$__($_($_GET{
    $___
}[$____]{
    $_____
}(),$flag));
```

#### 题目分析

```php
# 代码看着太不美观了，先自己美化一下
$_=function($__,$___)
{
    return $__==$___?$___:$__;
};
$$__($_($_GET{$___}[$____]{$_____}(),$flag));
```

```
整个思路就是定义一个函数，接收两个参数，利用三目运算符比较传入的两个参数，如果弱相等，返回第二个参数，即flag，否则返回第一个参数。
下面的语句$_($_GET{$___}[$____]{$_____}(),$flag)是对定义的函数进行了调用传递了两个参数，
第一个参数：$_GET{$___}[$____]{$_____}()
$_GET{$___}[$____]{$_____}，中括号花括号一样的用法，简化下$_GET[$___][$____][$_____]，是个三维数组
第二个参数：$flag
但是如果只是调用，是只有返回值，没有回显的，$$__()的作用就体现出来啦，必须是一个打印函数
print_r()或者var_dump等等都可以。
```

```
由于自定义函数是弱类型比较，只需要返回一个数字0，就可以和$flag弱类型相等成立，json_last_error函数符合要求，phpinfo()也可以。
```

#### 知识点

- ##### phpinfo()=='任意字符串'

- ##### 0也弱等于字符串， 0 == ‘字符串’

- ##### json_last_error() 函数是 int(0)

- ##### php中，中括号和花括号可等同

  ```
  $_GET{$___}[$____]{$_____}等价于$_GET[$___][$____][$_____]，
  是个三维数组
  ```

#### payload

```
?__=x&x=var_dump&___=a&____=b&_____=c&a[b][c]=json_last_error

?__=a&a=print_r&___=x&____=b&_____=c&x[b][c]=phpinfo

不能直接让__=var_dump，等等，因为所有的_都是变量名，$_是变量，需要给变量再赋值。
```

## 初六

```php
include "flag.php";

class happy2year{

    private $secret;
    private $key;

    function __wakeup(){
        $this->secret="";
    }
    
    function __call($method,$argv){
        
        return call_user_func($this->key, array($method,$argv));
    }


    function getSecret($key){
        $key=$key?$key:$this->key;
        return $this->createSecret($key);    
    }


    function createSecret($key){
        return base64_encode($this->key.$this->secret);
    }

    function __get($arg){
        global $flag;
        $arg="get".$arg;
        $this->$arg = $flag;
        return $this->secret;
    }

    function __set($arg,$argv){
        $this->secret=base64_encode($arg.$argv);
        
    }

    function __invoke(){
        
        return $this->$secret;
    }
    

    function __toString(){
    
        return base64_encode($this->secret().$this->secret);
    }

    
    function __destruct(){
        
        $this->secret = "";
    }
    


}

highlight_file(__FILE__);
error_reporting(0);
$data=$_POST['data'];
$key = $_POST['key'];
$obj = unserialize($data);
if($obj){
    $secret = $obj->getSecret($key);
    print("你提交的key是".$key."\n生成的secret是".$secret);
}
```

#### 题目分析

```php
	function __get($arg){
        global $flag;
        $arg="get".$arg;
        $this->$arg = $flag;
        return $this->secret;
    }
```

```
关键函数__get，先根据这个函数往回倒推回去
根据$this->$arg = $flag;可知，触发了set函数
__set()，用于将数据写入不可访问的属性

set函数的$this->secret=base64_encode($arg.$argv);，得出$arg="get",$argv=$flag，将secret的值和flag联系起来，$this->secret=base64_encode("get".$flag)。

然后倒推怎么触发__get函数？
__get()，用于从不可访问的属性读取数据或者不存在这个键都会调用此方法。
简单来说，要么是调用不存在的属性，要么调用私有变量。

这里想到了一开始的私有变量secret，要想调用secert，就需要触发invoke函数，return $this->$secret;
__invoke()，尝试将对象调用为函数时触发

为了触发invoke函数，观察到了call函数的return call_user_func($this->key, array($method,$argv));
call_user_func()函数把key作为了函数名来使用，这里提供了思路，可以将key赋值为当前对象
__call()，在对象上下文中调用不可访问的方法时触发

为了触发call函数，需要调用未定义的函数，即不存在的函数，发现了toString函数的return base64_encode($this->secret().$this->secret);，secret()就是未定义的函数
__toString()，把类、对象当作字符串使用时触发

为了触发toString函数，就要把对象当作字符串处理，观察到createSecret函数的return base64_encode($this->key.$this->secret);，将我们key对象当作了字符串进行拼接。

观察createSecret函数，发现getSecret函数调用了此函数。

由此整条反序列化链构造完成。
```

#### 知识点

##### 魔术方法

```
__wakeup() //执行unserialize()，会先调用这个函数
__sleep() //执行serialize()，会先调用这个函数
__destruct() //对象被销毁时触发
__call() //在对象上下文中调用不可访问的方法时触发
__callStatic() //在静态上下文中调用不可访问的方法时触发
__get() //用于从不可访问的属性读取数据或者不存在这个键都会调用此方法
__set() //用于将数据写入不可访问的属性
__isset() //在不可访问的属性上调用isset()或empty()触发
__unset() //在不可访问的属性上使用unset()触发
__toString() //把类当作字符串使用时触发
__invoke() //当尝试将对象调用为函数时触发
```

##### php构造方法__construct()

1、构造方法__construct()是一种结构特有的特殊方法。

2、该方法由系统规定，开发人员在定义时只需写一次，有构造方法的类在实例化对象后，对象自动调用。

##### php魔术方法__invoke()

1、直接调用对象名当方法使用时，就调用的是__invoke()方法。

2、对象本身不能直接当函数用。如果去掉__invoke()方法，还是将对象当做方法来使用时，就会报错。

##### php函数call_user_func

```
call_user_func()是PHP中的内置函数，用于调用第一个参数给定的回调并将其余参数作为参数传递。它用于调用用户定义的函数。
```

函数作用：该函数主要用于通过函数名去调用该函数，除了调用函数，还可以调用对象的方法

```
mixed call_user_func ( $function_name[, mixed $value1[, mixed $... ]])
```

$function_name：已定义函数列表中函数调用的名称。它是一个字符串类型参数。
$value：混合值。一个或多个要传递给函数的参数。

[PHP call_user_func()实例讲解](http://www.manongjc.com/detail/30-hhbxpwxqpauzxeg.html)

#### payload

```
class happy2year{

    private $secret;
    private $key;
	function __construct()
	{
		$this->key = $this;
	}
}
echo urlencode(serialize(new happy2year()));

POST:data=O%3A10%3A%22happy2year%22%3A2%3A%7Bs%3A18%3A%22%00happy2year%00secret%22%3BN%3Bs%3A15%3A%22%00happy2year%00key%22%3Br%3A1%3B%7D

提交之后，页面回显：
你提交的key是 生成的secret是V2pKV01Ga3pVbTFqTW1oMlpETjBiVTlVV21sT1JGVjVUV2t3TVU5WFJtbE1WRkY1VGxSSmRGbHRUbTFaYVRGc1drUlJlVTFVUlRWUFYwVTBUMFJrT1ZveVZqQlpNMUp0WXpKb2RtUXpkRzFQVkZwcFRrUlZlVTFwTURGUFYwWnBURlJSZVU1VVNYUlpiVTV0V1dreGJGcEVVWGxOVkVVMVQxZEZORTlFWkRrPQ==

将内容进行三次base64解码，因为在类happy2year()中，一共被编码了三次。
```

```
$key = new happy2year();
在给 $key 变量赋值时，会创建一个新的 happy2year 对象，并将其分配给 $key。
然而，在构造函数 __construct() 中，又试图创建一个新的 happy2year 对象并将其分配给局部变量 $key。
这会导致递归的无限循环，因为每次创建新的 happy2year 对象时，都会再次调用构造函数，又创建一个新的 happy2year 对象，以此类推，形成无限递归。

$this->key = $this;
这将类的当前实例赋值给 $key 属性，而不是创建一个新的 happy2year 对象。
$this->key 是将当前对象的引用分配给 $key 属性的一种方式。使用 $this 引用表示当前类的实例，因此 $this->key 表示在当前对象中创建一个属性 $key 并将其赋值为当前对象本身。
```

