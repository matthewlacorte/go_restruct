// First Go program
package main
 
import (
    "fmt"
	"strconv"
	"reflect"
)

// Declare c2c server struct
type c2cServer struct {
	url string
	port int
	command string
	response string
}


// Store hackee's cc
type genTest struct {
	testString string
	testInt16 int16
	testInt int
	testFloat float32
	testArray []int32
	testFunc func()
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
	// fmt.Printf("%#v\n\n\n", secret_c2c)
	fmt.Println(reflect.TypeOf(secret_c2c))


	var test *genTest
	test = new(genTest)

	test.testString = "this is my test to test"
	test.testInt16 = -744
	test.testInt = 102030
	test.testFloat = 1.234
	test.testArray = []int32{1, 2, 3, 4}
	// []int32{1, 2, 3}
	test.testFunc = func() { fmt.Println("GO RESTRUCT IS NEAT") }

	test.testFunc()

	fmt.Printf("%#v\n", test)
}

