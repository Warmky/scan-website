package utils

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"scan-website/models"
	"strings"
)

// 实际连接测试相关函数
func RunZGrab2WithResult(protocol, hostname, port, mode string) (bool, *models.ConnectInfo, error) {
	fmt.Print("Running test\n")

	// pythonPath := "python3" //linux
	pythonPath := "python" //windows
	scriptPath := "/home/wzq/scan-website/tlscheck/test_tls.py"

	cmd := exec.Command(pythonPath, scriptPath,
		"--protocol", protocol,
		"--host", hostname,
		"--port", port,
		"--mode", mode,
	)

	output, err := cmd.CombinedOutput()
	fmt.Println("Raw output:\n", string(output))

	if err != nil {
		return false, nil, fmt.Errorf("execution error: %v, output: %s", err, string(output))
	}
	var result models.ConnectInfo
	if err := json.Unmarshal(output, &result); err != nil {
		return false, nil, fmt.Errorf("invalid JSON output: %v", err)
	}

	if !result.Success {
		return false, nil, fmt.Errorf("TLS test failed: %s", result.Error)
	}

	return true, &result, nil
}

func checkConnectSuccess(result map[string]interface{}, protoType string) (bool, error) {
	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("data 字段缺失或类型错误")
	}

	protoData, ok := data[protoType].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("%s 字段缺失或类型错误", protoType)
	}

	status, ok := protoData["status"].(string)
	if !ok {
		return false, fmt.Errorf("status 字段缺失或类型错误")
	}

	// 若连接成功
	if status == "success" {
		return true, nil
	}

	// 如果包含 error 字段，提取错误信息
	if errStr, exists := protoData["error"].(string); exists {
		// 检查是否为 no such host 错误
		if strings.Contains(errStr, "no such host") {
			return false, fmt.Errorf("fail to connect: no such host")
		}
		return false, fmt.Errorf("fail to connect: %s", errStr)
	}

	return false, fmt.Errorf("fail to connect, status: %s", status)
}

func IsNoSuchHostError(err error) bool { //4.22Go->python
	// return err != nil && strings.Contains(err.Error(), "no such host")
	return err != nil && strings.Contains(err.Error(), "Name or service not known")
}

// 生成 CSV 文件，zgrab2 从该文件读取输入
func writeCSV(hostname string) (string, error) {
	// 创建临时文件
	tmpFile, err := os.CreateTemp("", "zgrab2_*.csv") // 生成唯一的临时文件
	if err != nil {
		return "", fmt.Errorf("无法创建临时文件: %v", err)
	}
	defer tmpFile.Close() // 关闭文件
	fmt.Printf("CSV 文件已创建: %s\n", tmpFile.Name())
	// 写入 CSV 内容
	writer := csv.NewWriter(tmpFile)
	defer writer.Flush() // 确保数据写入磁盘

	// // zgrab2 需要的 CSV 结构，通常包含 "ip" 或 "domain" 列
	// err = writer.Write([]string{"domain"}) // 设置 CSV 头部
	// if err != nil {
	// 	return "", fmt.Errorf("写入 CSV 头部失败: %v", err)
	// }
	//会额外读取domain为domain的，所以删去

	err = writer.Write([]string{hostname}) // 写入数据
	if err != nil {
		return "", fmt.Errorf("写入 CSV 数据失败: %v", err)
	}

	// 返回文件路径
	return tmpFile.Name(), nil
}

// func RunZGrab2(protocoltype, hostname, port string, tlsMode string) (bool, error) {
// 	// 生成临时 CSV 文件
// 	csvfile, err := writeCSV(hostname)
// 	if err != nil {
// 		fmt.Println("CSV 文件未创建")
// 		return false, fmt.Errorf("fail to create csv file: %v", err)
// 	}
// 	defer os.Remove(csvfile) // 开发阶段保留也可以先注释掉这行

// 	// 构造命令参数
// 	args := []string{protocoltype, "--port", port, "-f", csvfile}
// 	if tlsMode == "starttls" {
// 		args = append(args, "--starttls")
// 	} else if tlsMode == "tls" {
// 		// 注意协议后缀变化
// 		tlsFlag := fmt.Sprintf("--%ss", protocoltype)
// 		args = append(args, tlsFlag)
// 	}

// 	// 执行 zgrab2 命令
// 	zgrabPath := "./zgrab2"
// 	cmd := exec.Command(zgrabPath, args...)

// 	var out bytes.Buffer
// 	var stderr bytes.Buffer
// 	cmd.Stdout = &out
// 	cmd.Stderr = &stderr

// 	fmt.Println("Running command:", cmd.String())

// 	err = cmd.Run()
// 	if err != nil {
// 		fmt.Println("Error running command:", err)
// 		fmt.Println("Stderr:", stderr.String())
// 		fmt.Println("Stdout:", out.String())
// 		return false, fmt.Errorf("zgrab2 执行失败: %v\nStderr: %s", err, stderr.String())
// 	}

// 	fmt.Println("Raw JSON Output:", out.String())

// 	var result map[string]interface{}
// 	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
// 		return false, fmt.Errorf("解析 JSON 失败: %v", err)
// 	}

//		return checkConnectSuccess(result, protocoltype)
//	}//4.22

func RunZGrab2(protocol, hostname, port, mode string) (bool, error) { //4.22python
	fmt.Print("Running test\n")

	// pythonPath := "python3" //linux
	pythonPath := "python" //windows
	scriptPath := "/home/wzq/scan-website/tlscheck/test_tls.py"

	cmd := exec.Command(pythonPath, scriptPath,
		"--protocol", protocol,
		"--host", hostname,
		"--port", port,
		"--mode", mode,
	)

	output, err := cmd.CombinedOutput()
	fmt.Println("Raw output:\n", string(output))

	if err != nil {
		return false, fmt.Errorf("execution error: %v, output: %s", err, string(output))
	}

	// 定义结构体用于解析
	var result models.ConnectInfo
	if err := json.Unmarshal(output, &result); err != nil {
		return false, fmt.Errorf("invalid JSON output: %v", err)
	}

	if !result.Success {
		return false, fmt.Errorf("TLS test failed: %s", result.Error)
	}

	// 打印信息
	fmt.Printf("TLS Version: %s\n", result.Info.Version)
	fmt.Printf("Cipher: %v\n", result.Info.Cipher)
	fmt.Printf("TLS CA: %.40s...\n", result.Info.TLSCA) // 只显示前40字符
	//fmt.Printf("Auth: %v\n", result.Info.Auth)//因为smtp/imap的该字段结构不一样，所以没有打印

	return true, nil
}
