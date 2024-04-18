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


// Main function
func main() {

	// Create secret c2c struct
	secret_c2c := &c2cServer{
		url: "www.donttrustme.com/ever",
		port: 80,
		command: "im_alive",
	}

	// Totally real example of sending an I'm alive check to c2c server
	fmt.Printf("Phoning home...\n")
	fmt.Printf(secret_c2c.url + ":" + strconv.Itoa(secret_c2c.port) + "\n")
	fmt.Printf("> " + secret_c2c.command + "\n")

	secret_c2c.response = "this is a real response from the C2C server. I promise."

	fmt.Printf("> " + secret_c2c.response + "\n\n")

	fmt.Println(secret_c2c)
}

