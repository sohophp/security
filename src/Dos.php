<?php

namespace Sohophp\Security;

use ErrorException;

/**
 * Denial of Service
 * @package Sohophp\Security
 */
final class Dos
{
    /**
     * @var DosConfig
     */
    private $config;

    /**
     * @var string|null
     */
    private $ip;

    /**
     * 加入黑名单时执行的函数
     * @var callable
     */
    private $blocking_callback;
    /**
     * @var array 调试信息
     */
    private $debug_messages = [];
    /**
     * @var string 当前网址
     */
    private $uri;


    /**
     * Dos constructor.
     * @param DosConfig|null $config
     */
    public function __construct(?DosConfig $config = null)
    {

        $this->ip = $_SERVER['REMOTE_ADDR'];
        $this->uri = $_SERVER['REQUEST_URI'];
        $this->config = $config ?? new DosConfig();
        $this->addDebugMessage("[{$this->ip}] {$this->uri}");
        $this->autoClean();
    }

    /**
     * @return string
     * @throws ErrorException
     */
    private function getDir(): string
    {
        $dir = $this->config->getDataDirectory();
        if (!is_dir($dir) && !@mkdir($dir, 0777, true)) {
            throw new ErrorException("Dos: Failed to create folders");
        }

        $dir = rtrim($dir, '/') . '/' . date("Ymd") . '/' . date('H');
        $ip_path = explode('.', $this->ip);
        $dir .= '/' . implode("/", $ip_path);
        if (!is_dir($dir) && !@mkdir($dir, 0777, true)) {
            throw new ErrorException("Dos: Failed to create folders");
        }

        return $dir;
    }

    /**
     * @return bool
     * @throws ErrorException
     */
    public function refused(): bool
    {

        $ip = $this->ip;
        if (!$ip) {
            return true;
        }
        $methods = $this->config->getListenMethods();
        if (!in_array("ANY", $methods) && !in_array($_SERVER['REQUEST_METHOD'], $methods)) {
            $this->addDebugMessage("method ".$_SERVER["REQUEST_METHOD"]."不是".join("|",$methods)."之一");
            return false;
        }

        if (in_array($ip, $this->config->getWhiteList())) {
            $this->addDebugMessage("The $ip in whitelist");
            return false;
        }

        /**
         * 如果在黑名单中，更新拉黑时间并返回真
         */
        if ($this->inBlackList()) {
            $this->addToBlackList();
            return true;
        }

        $dir = $this->getDir();
        $filename = $dir . '/' . md5($this->uri);
        $page_count = 1;
        if (!file_exists($filename)) {
            $data = ["count" => 1];
            file_put_contents($filename, json_encode($data));
            chmod($filename, 0777);
        } elseif (filemtime($filename) + $this->config->getPageInterval() < time()) {
            $data = ["count" => 1];
            file_put_contents($filename, json_encode($data));
        } else {
            $data = json_decode(file_get_contents($filename), true);
            if (!$data) {
                $data = ["count" => 1];
            } else {
                $page_count = $data['count'] + 1;
                $this->addDebugMessage('page count ' . $page_count);
                $data["count"] = $page_count;
            }
            file_put_contents($filename, json_encode($data));
        }

        /**
         * 单面请求超过配置数量，加入黑名称并返回真
         */
        if ($page_count > $this->config->getPageCount()) {
            $this->addToBlackList();
            return true;
        }

        $site_filename = $dir . "/site";
        $site_count = 1;
        if (!file_exists($site_filename)) {
            $data = ["count" => 1];
            file_put_contents($site_filename, json_encode($data));
        } elseif (filemtime($site_filename) + $this->config->getSiteInterval() < time()) {
            $data = ["count" => 1];
            file_put_contents($site_filename, json_encode($data));
        } else {
            $data = json_decode(file_get_contents($site_filename), true);
            if (!$data) {
                $data = ["count" => 1];
            } else {
                $site_count = $data['count'] + 1;
                $this->addDebugMessage('site_count ' . $site_count);
                $data['count'] = $site_count;
            }
            file_put_contents($site_filename, json_encode($data));
        }

        /**
         * 站点请求数量超过配置数量，加入黑名单并返回真
         */
        if ($site_count > $this->config->getSiteCount()) {
            $this->addToBlackList();
            return true;
        }

        return false;

    }


    /**
     * @param string $message
     */
    private function addDebugMessage(string $message)
    {
        $this->debug_messages[] = $message;
    }

    /**
     * @return array 返回全部调试消息
     */
    public function getDebugMessages(): array
    {
        return $this->debug_messages;
    }

    /**
     * 加入黑名单
     * @throws ErrorException
     */
    public function addToBlackList()
    {
        $dir = $this->getDir();
        $filename = $dir . '/black-list';
        $blocking_period = time() + $this->config->getBlockingPeriod();
        $this->addDebugMessage("Locked from " . date('Y-m-d H:i:s') . ' to ' . date("Y-m-d H:i:s", $blocking_period));
        file_put_contents($filename, json_encode(["blocking_period" => $blocking_period]));
        chmod($filename, 0777);

        if (is_callable($this->blocking_callback)) {
            $args = [];
            call_user_func($this->blocking_callback, $args);
        }
    }

    /**
     * 是否在黑名单
     * @return bool
     * @throws ErrorException
     */
    public function inBlackList(): bool
    {
        $dir = $this->getDir();
        $filename = $dir . '/black-list';
        if (!is_file($filename)) {
            return false;
        }
        $data = file_get_contents($filename);
        $data = json_decode($data, true);
        if (!$data) {
            return false;
        }

        $blocking_period = $data['blocking_period'] ?? 0;

        $inBlockList = $blocking_period > time();
        if ($inBlockList) {
            $this->addDebugMessage("Locked to " . date("Y-m-d H:i:s", $blocking_period));
        }

        return $inBlockList;
    }

    /**
     * @param callable $blocking_callback
     * @return $this
     */
    public function onBlocking(callable $blocking_callback): self
    {
        $this->$blocking_callback = $blocking_callback;
        return $this;
    }

    /**
     * @return bool
     */
    private function autoClean(): bool
    {

        if (rand(0, 500) != 250) {
            return false;
        }

        $this->addDebugMessage("do clean");
        return $this->rmdir($this->config->getDataDirectory());
    }

    /**
     * @param $dir
     * @return bool
     */
    private function rmdir($dir): bool
    {
        if (!is_dir($dir)) {
            return false;
        }

        $hasFiles = false;
        $d = opendir($dir);
        while (false !== ($file = readdir($d))) {
            $filename = $dir . '/' . $file;

            if (in_array($file, ['.', '..'])) {
                continue;
            }

            if (filemtime($filename) + $this->config->getBlockingPeriod() + 3600 * 24 > time()) {
                $hasFiles = true;
                continue;
            } elseif (is_dir($filename)) {
                if (!$this->rmdir($filename)) {
                    $hasFiles = true;
                }
            } elseif (is_file($filename)) {
                if (!@unlink($filename)) {
                    $hasFiles = true;
                }
            }
        }
        closedir($d);
        return !$hasFiles && @rmdir($dir);
    }

    /**
     *
     */
    public function guard()
    {
        try {
            if ($this->refused()) {
                $this->sendResponse();
            }
        } catch (ErrorException $e) {
            error_log($e->getMessage());
        }
    }

    public function run()
    {
        $this->guard();
    }

    /**
     *
     */
    public function sendResponse()
    {
        header_remove();
        http_response_code(403);
        echo <<<"HTML"
<html lang="en">
<head>
<title>403 Forbidden</title>
</head>
<body>
<h1 class="dos">Forbidden</h1>
<p>You don't have permission to access {$this->uri} on this server.</p>
</body>
</html>
HTML;
        exit;
    }
}
