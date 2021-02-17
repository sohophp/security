# Sohophp/Security

## 介绍 
帮助防止暴力破解，暴力攻击 的PHP类
限制单页每秒请求数和站点每秒请求数

## 安装方法

```Bash
npm install sohophp/security
```


## 使用方法

```PHP

$config = new Sohophp\Security\DosConfig();
$dos = new Sohophp\Security\Dos($config);
$dos->run();

```
