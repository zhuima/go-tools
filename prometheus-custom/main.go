package main

import (
	"log"
	"net/http"
	"time"

	"fmt"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	cache "github.com/chenyahui/gin-cache"
	"github.com/chenyahui/gin-cache/persist"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

var (
	domainList = []string{"www.baidu.com", "www.jd.com", "www.golangbot.com"}
)

// 定义域名数据数据返回
type DomainInfo struct {
	DomainName     string `json:"domain_name"`
	ExpirationDate string `json:"expiration_date"`
	ExpirationDays int64  `json:"expiration_days"`
}

// define a struct
type expireCollector struct {
	// 定义域名清单
	domainMetric *prometheus.Desc
	sslMetric    *prometheus.Desc
}

func newExpireCollector() *expireCollector {
	// Metric
	return &expireCollector{
		domainMetric: prometheus.NewDesc("domain_expire_time",
			"Show domain expire time", []string{"domain_name", "expire_time"}, nil),
		sslMetric: prometheus.NewDesc("ssl_expire_time",
			"Show ssl expire time", []string{"domain_name", "expire_time"}, nil),
	}
}

func (collector *expireCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.domainMetric
	ch <- collector.sslMetric
}

func (collector *expireCollector) Collect(ch chan<- prometheus.Metric) {

	for _, domain := range domainList {
		domainInfo, err := domainExpireCheck(domain)
		if err != nil {
			log.Println("get domainInfo failed")
			return
		}

		ch <- prometheus.MustNewConstMetric(collector.domainMetric, prometheus.GaugeValue, float64(domainInfo.ExpirationDays), domainInfo.DomainName, domainInfo.ExpirationDate)
		ch <- prometheus.MustNewConstMetric(collector.sslMetric, prometheus.GaugeValue, float64(domainInfo.ExpirationDays), domainInfo.DomainName, domainInfo.ExpirationDate)
	}

}

func domainExpireCheck(domainName string) (DomainInfo, error) {

	// 大小写转换，避免用户误输入
	// 判断用户是否是输入的顶级域名，如果不是则需要处理下,这里使用副本的形式进行截取，避免内存不回收现象
	realname := make([]string, 2)
	splitDomainName := strings.Split(strings.ToLower(domainName), ".")
	copy(realname, splitDomainName[(len(splitDomainName)-2):])
	// fmt.Println("realname", strings.Join(realname, "."))
	whoisCurrentTime := time.Now()
	whois_result, err := whois.Whois(strings.Join(realname, "."))
	fmt.Println("whois cost time", time.Since(whoisCurrentTime))
	if err != nil {
		fmt.Println("Error in whois lookup : %v ", err)
		os.Exit(1)
	}

	// fmt.Println(result)

	result, err := whoisparser.Parse(whois_result)
	if err != nil {
		fmt.Println("Error in whois Parse : %v ", err)
		os.Exit(1)
	}

	// 获取当前时间
	currentTime := time.Now()
	// currentTime := time.Now().Format("02/01/2006")
	// 根据过期时间求差 获取距离过期时间还剩余多少天
	difference := result.Domain.ExpirationDateInTime.Sub(currentTime)

	domaininfo := &DomainInfo{
		DomainName:     domainName,
		ExpirationDate: result.Domain.ExpirationDate,
		ExpirationDays: int64(difference.Hours() / 24),
	}

	return *domaininfo, nil

}

func homePage(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "PONG",
	})
}

func prometheusHandler() gin.HandlerFunc {
	h := promhttp.Handler()

	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

func main() {
	r := gin.New()

	r.Use(gin.Logger(), gin.Recovery())
	memoryStore := persist.NewMemoryStore(1 * time.Minute)

	// 移除默认的监控项
	// prometheus.Unregister()
	// , or, even better, promhttp.Handler()
	prometheus.Unregister(prometheus.NewGoCollector())

	// 添加自定义监控项
	domain := newExpireCollector()
	prometheus.MustRegister(domain)
	r.GET("/metrics", cache.CacheByRequestPath(memoryStore, 2*time.Second), gin.WrapH(promhttp.Handler()))
	// r.GET("/metrics", prometheusHandler())
	r.GET("/", homePage)

	r.Run()
}
