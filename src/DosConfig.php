<?php

namespace Sohophp\Security;

use ArrayAccess;

/**
 * Class DosConfig
 * @package Sohophp\Security
 */
final class DosConfig implements ArrayAccess
{
    /**
     * IP 白名單
     *
     * @var array
     */
    private array $white_list = [];
    /**
     * 單頁每page_interval秒最大請求數
     *
     * @var integer
     */
    private int $page_count = 2;
    /**
     * 封鎖週期
     *
     * @var integer
     */
    private int $blocking_period = 10;

    /**
     * 站點每秒最大請求數
     *
     * @var integer
     */
    private int $site_count = 50;

    /**
     * 每頁時間間隔，單位秒
     *
     * @var integer
     */
    private int $page_interval = 1;
    /**
     * 站點時間間隔，單位秒
     *
     * @var integer
     */
    private int $site_interval = 1;
    /**
     * 收信地址
     *
     * @var array
     */
    private array $email_addresses = [];
    /**
     * 記錄文件存放路徑
     *
     * @var string
     */
    private string $data_directory;
    /**
     * @var array|string[] 监听的请求方法
     */
    private array $listen_methods = ['ANY'];
    /**
     * @var bool 是否记录请求详情
     */
    private bool $spread = false;
    /**
     * @var bool 是否使用调试
     */
    private bool $debug = false;

    public function __construct(array $options = [])
    {
        $options = array_replace([
            'data_directory' => sys_get_temp_dir()
        ], $options);
        foreach ($options as $name => $value) {
            $this->{$name} = $value;
        }
    }


    public function offsetExists(mixed $offset):bool
    {
        return isset($this->{$offset});
    }

    public function offsetGet(mixed $offset):mixed
    {
        return $this->{$offset};
    }

    public function offsetSet(mixed $offset, mixed $value):void
    {
        $this->{$offset} = $value;
    }

    public function offsetUnset(mixed $offset):void
    {
        unset($this->{$offset});
    }

    /**
     * @return array
     */
    public function getWhiteList(): array
    {
        return $this->white_list;
    }

    /**
     * @param array $white_list
     */
    public function setWhiteList(array $white_list): void
    {
        $this->white_list = $white_list;
    }

    public function addWhiteList(...$white_list):void
    {
        foreach ($white_list as $ip) {
            $this->white_list[] = $ip;
        }
    }

    /**
     * @return int
     */
    public function getPageCount(): int
    {
        return $this->page_count;
    }

    /**
     * @param int $page_count
     */
    public function setPageCount(int $page_count): void
    {
        $this->page_count = $page_count;
    }

    /**
     * @param int $page_count
     * @return DosConfig
     */
    public function withPageCount(int $page_count): DosConfig
    {
        $clone = clone $this;
        $clone->setPageCount($page_count);
        return $clone;
    }

    /**
     * @return int
     */
    public function getBlockingPeriod(): int
    {
        return $this->blocking_period;
    }

    /**
     * @param int $blocking_period
     */
    public function setBlockingPeriod(int $blocking_period): void
    {
        $this->blocking_period = $blocking_period;
    }

    /**
     * @param int $blocking_period
     * @return DosConfig
     */
    public function withBlockingPeriod(int $blocking_period): DosConfig
    {
        $clone = clone $this;
        $clone->setBlockingPeriod($blocking_period);
        return $clone;
    }

    /**
     * @return int
     */
    public function getSiteCount(): int
    {
        return $this->site_count;
    }

    /**
     * @param int $site_count
     */
    public function setSiteCount(int $site_count): void
    {
        $this->site_count = $site_count;
    }

    /**
     * @param int $site_count
     * @return DosConfig
     */
    public function withSiteCount(int $site_count): DosConfig
    {
        $clone = clone $this;
        $clone->setSiteCount($site_count);
        return $clone;
    }

    /**
     * @return int
     */
    public function getPageInterval(): int
    {
        return $this->page_interval;
    }

    /**
     * @param int $page_interval
     */
    public function setPageInterval(int $page_interval): void
    {
        $this->page_interval = $page_interval;
    }

    /**
     * @return int
     */
    public function getSiteInterval(): int
    {
        return $this->site_interval;
    }

    /**
     * @param int $site_interval
     */
    public function setSiteInterval(int $site_interval): void
    {
        $this->site_interval = $site_interval;
    }

    /**
     * @return array
     */
    public function getEmailAddresses(): array
    {
        return $this->email_addresses;
    }

    /**
     * @param array $email_addresses
     */
    public function setEmailAddresses(array $email_addresses): void
    {
        $this->email_addresses = $email_addresses;
    }

    /**
     * @return string
     */
    public function getDataDirectory(): string
    {
        return $this->data_directory;
    }

    /**
     * @param string $data_directory
     */
    public function setDataDirectory(string $data_directory): void
    {
        $this->data_directory = $data_directory;
    }

    /**
     * @param string $data_directory
     * @return DosConfig
     */
    public function withDataDirectory(string $data_directory): DosConfig
    {
        $clone = clone $this;
        $clone->setDataDirectory($data_directory);
        return $clone;
    }

    /**
     * @return string
     */
     public function getLogDirectory(): string
    {
        return rtrim($this->getDataDirectory(), '/') . '/DoS_log';
    }

    /**
     * @param array $listen_methods
     */
    public function setListenMethods(array $listen_methods)
    {
        $this->listen_methods = array_map("stopper", $listen_methods);
    }

    /**
     * @param array $listen_methods
     * @return DosConfig
     */
    public function withListenMethods(array $listen_methods): DosConfig
    {
        $clone = clone $this;
        $clone->setListenMethods($listen_methods);
        return $clone;
    }

    /**
     * @return string[]
     */
    public function getListenMethods(): array
    {
        return $this->listen_methods;
    }

    /**
     * @return bool
     */
    public function isSpread(): bool
    {
        return $this->spread;
    }

    /**
     * @param bool $spread
     */
    public function setSpread(bool $spread): void
    {
        $this->spread = $spread;
    }

    /**
     * @param bool $spread
     * @return DosConfig
     */
    public function withSpread(bool $spread): DosConfig
    {
        $clone = clone $this;
        $clone->setSpread($spread);
        return $clone;
    }

    /**
     * @return bool
     */
    public function isDebug(): bool
    {
        return $this->debug;
    }

    /**
     * @param bool $debug
     */
    public function setDebug(bool $debug): void
    {
        $this->debug = $debug;
    }

    /**
     * @param bool $debug
     * @return DosConfig
     */
    public function withDebug(bool $debug): DosConfig
    {
        $clone = clone $this;
        $clone->setDebug($debug);
        return $clone;
    }

    /**
     * @return array
     */
    public function toArray(): array
    {
        return [
            'white_list' => $this->white_list,
            'page_count' => $this->page_count,
            'blocking_period' => $this->blocking_period,
            'site_count' => $this->site_count,
            'page_interval' => $this->page_interval,
            'site_interval' => $this->site_interval,
            'email_addresses' => $this->email_addresses,
            'data_directory' => $this->data_directory,
            'listen_methods' => $this->listen_methods
        ];
    }

    /**
     * @return array
     */
    public function __debugInfo():array
    {
        return $this->toArray();
    }
}
