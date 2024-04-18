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


// Store hackee's cc
type creditCardInfo struct {
	number string
	cvv int16
	exp string
	name string
	zip int
	limit float32
}

// Steal hackee's cc
func steal() {
	fmt.Println("Let's steal a credit card")

	var cc *creditCardInfo
	cc = new(creditCardInfo)

	cc.number = "1337 1337 1337 1337"
	cc.cvv = 707
	cc.exp = "1/1/1970"
	cc.name = "Richard Long"
	cc.zip = 12345
	cc.limit = 125.62

	fmt.Println("Got the info!")

	fmt.Printf("%#v\n", cc)


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

	secret_c2c.response = "go_shopping"

	fmt.Println("> " + secret_c2c.response + "\n")
	fmt.Printf("%#v\n\n\n", secret_c2c)

	if secret_c2c.response == "go_shopping" {
		steal()
	}
}

