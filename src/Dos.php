<?php

namespace Sohophp\Security;

use Closure;
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
    private DosConfig $config;

    /**
     * @var string
     */
    private string $ip;

    /**
     * 加入黑名单时执行的函数
     * @var mixed|callable
     * \Closure|\callable
     */
    private mixed $blocking_callback = null;
    /**
     * @var array 调试信息
     */
    private array $debug_messages = [];
    /**
     * @var string 请求网址
     */
    private string $request_uri;
    /**
     * @var int 请求时间
     */
    private int $request_time;
    /**
     * @var string 请求方法
     */
    private string $request_method;
    /**
     * @var string 数据路径
     */
    private string $dir;

    /**
     * Dos constructor.
     * @param DosConfig|null $config
     */
    public function __construct(DosConfig $config = null)
    {

        $this->ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $this->request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $this->request_time = $_SERVER['REQUEST_TIME'] ?? '';
        $this->request_method = $_SERVER['REQUEST_METHOD'] ?? '';
        $this->config = $config ?? new DosConfig();
        $this->addDebugMessage("{$this->ip} [{$this->request_method}] {$this->request_uri}");
        $this->autoClean();
    }

    /**
     * @return string
     * @throws ErrorException
     */
    private function getDir(): string
    {
        if (!$this->dir) {
            $dir = $this->config->getLogDirectory();
            if (!is_dir($dir) && !@mkdir($dir, 0777, true)) {
                throw new ErrorException("Dos: Failed to create folders");
            }

            $dir = rtrim($dir, '/') . '/' . date("Ymd") . '/' . date('H');
            $ip_path = explode('.', $this->ip);
            $dir .= '/' . implode("/", $ip_path);
            if (!is_dir($dir) && !@mkdir($dir, 0777, true)) {
                throw new ErrorException("Dos: Failed to create folders");
            }
            $this->dir = $dir;
        }
        return $this->dir;
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

        if (in_array($ip, $this->config->getWhiteList())) {
            $this->addDebugMessage("The $ip in whitelist");
            return false;
        }

        if (!in_array('ANY', $this->config->getListenMethods())
            && !in_array($this->request_method, $this->config->getListenMethods())) {
            return false;
        }

        /**
         * 如果在黑名单中，更新拉黑时间并返回真
         */
        if ($this->inBlackList()) {
            return true;
        }

        $dir = $this->getDir();
        $data_info = [
            "REQUEST_URI" => $this->request_uri,
            "NOW" => microtime(true),
            "method" => $this->request_method,
            "REQUEST_TIME" => $this->request_time,
            //"USER_AGENT" => $_SERVER['HTTP_USER_AGENT']
        ];

        $filename = $dir . '/' . md5($this->request_uri);
        $count = 1;

        if (!file_exists($filename)) {
            touch($filename, $this->request_time, $this->request_time);
            chmod($filename, 0777);
            $data = ["count" => 1];
            if ($this->config->isSpread()) {
                $data_info['s'] = 1;
                $data_info['c'] = 1;
                $data['info'] = [$data_info];
            }
            file_put_contents($filename, json_encode($data));
            $this->addDebugMessage("page:第一次请求");
        } elseif (filemtime($filename) + $this->config->getPageInterval() < $this->request_time) {
            $data = ["count" => 1];
            if ($this->config->isSpread()) {
                $data_info['s'] = 2;
                $data_info['ss'] = microtime(true);
                $data_info['c'] = 1;
                $data['info'] = [$data_info];
            }
            file_put_contents($filename, json_encode($data));
            $this->addDebugMessage("page:上次请求过时");
        } else {
            $data = json_decode(file_get_contents($filename), true);
            if (!$data) {
                $data = ["count" => 1];
                if ($this->config->isSpread()) {
                    $data_info['s'] = 3;
                    $data_info['ss'] = microtime(true);
                    $data_info['c'] = 1;
                    $data['info'] = $data_info;
                }
                $this->addDebugMessage("page:JSON文件出错");
            } else {
                $count = $data['count'] + 1;
                $data["count"] = $count;
                if ($this->config->isSpread()) {
                    if (!isset($data['info'])) {
                        $data['info'] = [];
                    }
                    $data_info['s'] = 4;
                    $data_info['ss'] = microtime(true);
                    $data_info['c'] = $count;
                    $data['info'][] = $data_info;
                }
                $this->addDebugMessage('page: count ' . $count);
            }
            file_put_contents($filename, json_encode($data));
        }

        /**
         * 单面请求超过配置数量，加入黑名称并返回真
         */
        if ($count > $this->config->getPageCount()) {
            $this->addToBlackList("page: $this->request_uri  count " . $count . ">" . $this->config->getPageCount());
            $this->addDebugMessage("page: count " . $count . ">" . $this->config->getPageCount());
            if ($this->config->isSpread()) {
                foreach ($data['info'] ?? [] as $info) {
                    $this->addDebugMessage(print_r($info, true));
                }
            }
            return true;
        }

        $filename = $dir . "/site";
        $count = 1;

        if (!file_exists($filename)) {
            touch($filename, $this->request_time, $this->request_time);
            chmod($filename, 0777);
            $data = ["count" => 1];
            if ($this->config->isSpread()) {
                $data['info'] = [$data_info];
            }
            file_put_contents($filename, json_encode($data));
            $this->addDebugMessage("site: 第一次请求");
        } elseif (filemtime($filename) + $this->config->getSiteInterval() < $this->request_time) {
            $data = ["count" => 1];
            if ($this->config->isSpread()) {
                $data['info'] = [$data_info];
            }
            file_put_contents($filename, json_encode($data));
            $this->addDebugMessage("site: 上次请求过时，重新计算第一次请求");
        } else {
            $data = json_decode(file_get_contents($filename), true);
            if (!$data) {
                $data = ["count" => 1];
                if ($this->config->isSpread()) {
                    $data['info'] = [$data_info];
                }
                $this->addDebugMessage("site: JSON错误，重新计算");
            } else {
                $count = $data['count'] + 1;
                if ($this->config->isSpread()) {
                    if (!isset($data['info'])) {
                        $data['info'] = [];
                    }
                    $data['info'][] = $data_info;
                }
                $this->addDebugMessage('site: count ' . $count);
                $data['count'] = $count;
            }
            file_put_contents($filename, json_encode($data));
        }

        /**
         * 站点请求数量超过配置数量，加入黑名单并返回真
         */
        if ($count > $this->config->getSiteCount()) {
            $this->addToBlackList("site: " . $this->request_uri . " count $count > " . $this->config->getSiteCount());
            $this->addDebugMessage("site: count $count > " . $this->config->getSiteCount());
            if ($this->config->isSpread()) {
                foreach ($data['info'] ?? [] as $info) {
                    $this->addDebugMessage(print_r($info, true));
                }
            }
            return true;
        }

        return false;
    }

    /**
     * @param string $message
     */
    private function addDebugMessage(string $message)
    {
        if ($this->config->isDebug()) {
            $this->debug_messages[] = $message;
        }
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
     * @param string|null $message
     * @param array $data
     * @throws ErrorException
     */
    public function addToBlackList(?string $message = null, array $data = [])
    {
        $dir = $this->getDir();
        $filename = $dir . '/black-list';


        $blocking_period = $this->request_time + $this->config->getBlockingPeriod();
        $this->addDebugMessage("Locked from " . date('Y-m-d H:i:s') . ' to ' . date("Y-m-d H:i:s", $blocking_period));
        $data ["blocking_period"] = $blocking_period;
        if ($message != '') {
            $data['message'] = $message;
        }

        file_put_contents($filename, json_encode($data));
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
        $inBlockList = $blocking_period > $this->request_time;
        if ($inBlockList) {
            $this->addDebugMessage("Locked to " . $blocking_period . ":" . date("Y-m-d H:i:s", $blocking_period));
            $this->addDebugMessage("Locked info : " . ($data['message'] ?? ''));
            $this->addToBlackList($data['message']);
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
        return $this->rmdir($this->config->getLogDirectory());
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

            if (filemtime($filename) + $this->config->getBlockingPeriod() + 3600 * 24 > $this->request_time) {
                $hasFiles = true;
                continue;
            }

            if (is_dir($filename)) {
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
<p>You don't have permission to access {$this->request_uri} on this server.</p>
</body>
</html>
HTML;
        exit;
    }
}
