package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	urlStart    = "{"
	urlEnd      = "}"
	highlight   = color.New(color.ReverseVideo)
	infoLogger  *log.Logger
	errorLogger *log.Logger
	noreprint   string
	counter     = false
	co1         = false
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("请输入密钥: ")
	hexString, _ := reader.ReadString('\n')
	hexString = strings.TrimSuffix(hexString, "\r\n")
	key, err := hex.DecodeString(hexString)
	fmt.Print("请输入[IP:端口]: ")
	addr, _ := reader.ReadString('\n')
	//addr = strings.TrimSuffix(addr, "\n")
	addr = strings.TrimSuffix(addr, "\r\n")
	//Info(addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		Error(err)
		return
	}
	defer conn.Close()

	clearConsole()

	done := make(chan struct{}) // 创建一个通道用于同步

	go handleServerResponses(conn, key, done)
	//go handleServerResponses(conn, key)

	go func(key []byte) {
		for {
			reader := bufio.NewReader(os.Stdin)
			message, _ := reader.ReadString('\n')
			noreprint = message

			cipherText := cryp1([]byte(message), key)

			_, err := conn.Write(cipherText)
			if err != nil {
				fmt.Println("Error sending message to server:", err)
				Error(err)
				break
			}
			counter = true
		}
	}(key)

	<-done // 等待协程完成

	/*
		go func(key []byte) {
			for {
				reader := bufio.NewReader(os.Stdin)
				message, _ := reader.ReadString('\n')

				parsedInput := parseInput(message)

				cipherText := cryp1([]byte(parsedInput), key)

				conn.Write(cipherText)
			}
		}(key)
	*/
	/*reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			Error(err)
			break
		}

		parsedInput := parseInput(input)
		conn.Write([]byte(parsedInput))
	}*/
}

func parseInput(input string) (string, bool) {
	startIndex := strings.Index(input, urlStart)
	endIndex := strings.Index(input, urlEnd)

	if startIndex >= 0 && endIndex > startIndex {
		url := input[startIndex+len(urlStart) : endIndex]
		if co1 == true {
			co1 = false
		} else {
			print("->")
			highlight.Println(url)
		}
		return "", true
		//highlightURL(url)
		//return strings.ReplaceAll(input, urlStart+url+urlEnd, url)
	}

	return input, false
}

/*
func parseInput(input string) string {
	startIndex := strings.Index(input, urlStart)
	endIndex := strings.Index(input, urlEnd)

	if startIndex >= 0 && endIndex > startIndex {
		url := input[startIndex+len(urlStart) : endIndex]
		highlightURL(url)
		return strings.Replace(input, urlStart+url+urlEnd, url, 1)
	}

	return input
}*/
/*
func highlightURL(url string) {
	highlight.Println(url)
	if runtime.GOOS == "linux" {
		copyToClipboardLinux(url)
	}
	if runtime.GOOS == "windows" {
		ctwc(url)
	}
}

func copyToClipboardLinux(text string) {
	cmd := exec.Command("xclip", "-selection", "clipboard")
	cmd.Stdin = strings.NewReader(text)

	_, err := exec.LookPath("xclip")
	if err != nil {
		fmt.Println("xclip command not found. Cannot copy to clipboard.")
		return
	}

	err = cmd.Run()
	if err != nil {
		Error(err)
		fmt.Println("Error copying to clipboard:", err)
		Error(err)
	}
}

func ctwc(text string) {
	err := clipboard.WriteAll(text)
	if err != nil {
		fmt.Println("复制到剪贴板时出错:", err)
		return
	}
}
*/
func handleServerResponses(conn net.Conn, key []byte, done chan struct{}) {
	defer conn.Close()

	//reader := bufio.NewReader(conn)
	for {
		buffer := make([]byte, 1024)
		//n, err := reader.Read(buffer)
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Println("Error reading from connection:", err)
			Error(err)
			break
		}

		data := make([]byte, n)
		copy(data, buffer[:n])

		cipherText := string(data)
		plainText := uncryp1([]byte(cipherText), key)

		//cipherText := buffer[:n]
		//plainText := uncryp1(cipherText, key)

		co2, co := parseInput(strings.TrimRight(string(plainText), "\r\n"))

		if string(plainText) == noreprint && counter == true {
			counter = false
			co1 = true
		} else if co == false {
			fmt.Print("->", co2, "\n")
		}
	}

	close(done) // 通知协程已完成
}

/*
func handleServerResponses(conn net.Conn, key []byte) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		buffer := make([]byte, 1024)
		n, err := reader.Read(buffer)
		if err != nil {
			fmt.Println("Error reading from connection:", err)
			Error(err)
			break
		}

		cipherText := buffer[:n]
		plainText := uncryp1(cipherText, key)

		fmt.Println("Server:", plainText)
	}
}
*/
/*
func handleServerResponses(conn net.Conn, key []byte) {
	for {
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Println("Connection closed by server")
			break
		}

		cipherText := string(buffer[:n])
		plainText := uncryp1([]byte(cipherText), key)

		fmt.Println("Server:", plainText)
	}
	//*reader := bufio.NewReader(conn)
	for {
		msg, err := reader.ReadString('\n')
		if err != nil {
			Error(err)
			break
		}

		msg = strings.TrimSuffix(msg, "\n")
		fmt.Println(msg)
	}
}
*/
/*
func tf(intArray []int) string {
	var strArray []string

	for _, num := range intArray {
		strArray = append(strArray, strconv.Itoa(num))
	}

	str := strings.Join(strArray, "")

	trimmedStr := strings.TrimRight(str, "\r\n")

	return trimmedStr
}

func bytesToInts(bytes []byte) []int {
	ints := make([]int, len(bytes))

	for i, b := range bytes {
		ints[i] = int(b)
	}

	return ints
}
*/
func clearConsole() {
	cmd := exec.Command("clear")

	// 根据操作系统判断命令
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	}

	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error clearing console:", err)
		Error(err)
	}
}

// 加密数据
func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	//println(ciphertext)
	return ciphertext, nil
}

// 解密数据
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	//println(ciphertext)
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	//plaintext, err := gcm.Open(nil, nonce, encryptedData, nil) //???WHY DO N0T WORK???
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// 计算消息的SHA-256散列值
/*func calculateHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}*/

func cryp1(data, key []byte) []byte {
	// 加密数据
	ciphertext, err := encrypt(data, key)
	if err != nil {
		Error(err)
		panic(err)
	}

	// 计算散列值
	//hash := calculateHash(data)
	return ciphertext //, hash
}
func uncryp1(ciphertext, key []byte) []byte {

	// 解密数据
	plaintext, err := decrypt(ciphertext, key)
	if err != nil {
		Error(err)
		//panic(err)
		fmt.Println(err) //test mode
	}

	// 验证散列值
	/*if calculateHash(plaintext) == hash {
		Info(string(plaintext))
		return plaintext, "--transport_complete--"
	}*/
	Info(string(plaintext))
	return plaintext
}

func init() {
	// 创建日志文件夹
	logDir := "./logs"
	err := os.MkdirAll(logDir, os.ModePerm)
	if err != nil {
		log.Fatalf("无法创建日志文件夹: %s", err)
	}

	// 创建日志文件
	logFile := filepath.Join(logDir, fmt.Sprintf("log_%s.txt", time.Now().Format("20060102_150405")))
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("无法创建日志文件: %s", err)
	}

	// 初始化日志输出
	infoLogger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLogger = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// Info 打印一条信息日志
func Info(message string) {
	infoLogger.Println(message)
}

// Error 打印一条错误日志
func Error(err error) {
	errorLogger.Println(err)
}
