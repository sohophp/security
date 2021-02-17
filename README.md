# Sohophp/Security

## 介绍

帮助防止暴力破解，暴力攻击 的PHP类 限制单页每秒请求数和站点每秒请求数

## 安装方法

```Bash

composer require sohophp/security

```

## 使用方法

```PHP
$dos = new Sohophp\Security\Dos();
$dos->run();
```

## 修改配置方法

```PHP

$config = new Sohophp\Security\DosConfig();
//添加IP白名单
$config->addWhiteList('::1','127.0.0.1');
//单页每秒最大请求数
$config->setPageCount(3);
//站点每秒请求数
$config->setSiteCount(100);
//加入黑名单秒数，每次请求重置拉黑时间
$config->setBlockingPeriod(300);
//监听全部METHOD
//$config->setListenMethods(["ANY"]);
//监听以下METHOD
$config->setListenMethods(["POST","DELETE","PUT","OPTIONS"]);
$dos = new Sohophp\Security\Dos($config);
//自动运行，阻止时出现403 
//$dos->run();
//测试使用
try{

    if($dos->refused()){ 
        print_r($dos->getDebugMessages());
        die("已被拉黑");
    }
}catch (Exception $exception){
    error_log($exception->getMessage());
}

```
### 测试方法

连续刷新同一网址