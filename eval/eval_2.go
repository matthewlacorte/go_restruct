// First Go program
package main
 
import (
    "fmt"
	"strconv"
)

// Declare c2c server struct
type c2cServer struct {
	url string
	port int
	command string
	response string
}

// Info to gather from machine
type machineInfo struct {
	os string
	arch uint8
	mem_gigs uint8
	timezone string
	language string
}

// Gather machine info

func gather() {
	fmt.Println("Getting all machine info...")

	var mi *machineInfo
	mi = new(machineInfo)

	mi.os = "Windows95"
	mi.arch = 32
	mi.mem_gigs = 2
	mi.timezone = "UTC-1"
	mi.language = "pig latin"

	fmt.Println("Got the info!")

	fmt.Printf("%#v\n", mi)
}


// Main function
func main() {

	// Create secret c2c struct
	secret_c2c := &c2cServer{
		url: "www.donttrustme.com/ever",
		port: 80,
		command: "wut_do",
	}

	// Totally real example of sending an I'm alive check to c2c server
	fmt.Println("Phoning home...")
	fmt.Println(secret_c2c.url + ":" + strconv.Itoa(secret_c2c.port))
	fmt.Println("> " + secret_c2c.command)

	secret_c2c.response = "get_all_info"

	fmt.Println("> " + secret_c2c.response + "\n")
	fmt.Printf("%#v\n\n\n", secret_c2c)

	if secret_c2c.response == "get_all_info" {
		gather()
	}
}

