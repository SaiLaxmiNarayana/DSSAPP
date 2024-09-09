<?php
header("Content-Type: application/json");
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL); 
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
require_once 'configure.php';
require 'phpmailer/src/Exception.php';
require 'phpmailer/src/PHPMailer.php';
require 'phpmailer/src/SMTP.php';
require 'vendor/autoload.php';
require __DIR__ . '/otp/autoload.php';
require __DIR__ . '/vendor/autoload.php';
$conn = mysqli_connect("localhost", "root", "", "dss");
use Firebase\JWT\JWT;
use Twilio\Rest\Client;
use Dotenv\Dotenv;
// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

// Function to validate API key
function validateApiKeyFromHeader() {
    // Get the Authorization header value
    $headers = getallheaders();
    $authorizationHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
    
    // Log the extracted header value
    // Extract the API key from the Authorization header (assuming it follows the "Bearer" scheme)
    $apiKey = str_replace('Bearer ', '', $authorizationHeader);

    // Retrieve the expected API key from environment variable or config file
    $expectedApiKey = getenv('API_KEY');
    // Check if the provided API key matches the expected value
    if ($apiKey === $expectedApiKey) {
        return true; // API key is valid
    } else {
        return false; // API key is invalid
    }
}

 
 if(validateApiKeyFromHeader()) {
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['signup'])) {

    Signup();
}

// Login endpoint
elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
     Login() ;
}

// Send OTP endpoint
elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_otp'])) {
 
     Sentotp();
}

// Validate OTP endpoint
elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['validate_otp'])) {

    Validateotp();
}

// Reset password endpoint
elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_password'])) {
    
  ResetPassword();
}

  elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['DailyActivity_Submitting'])) {

     DailyActicitySubmitting($conn) ;
  }

  
elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_leave']))  {

    sendmailandstoringDatabse();
     
}

elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_reason']))  {

    submitReason(); 
}
elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['Insertid']))  {

    InsertID(); 
}
elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['Delete']))  {

    Delete(); 
}

elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['LeaveRequests']))  {

    processLeaveRequest();
}
elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['Employeeattendence']))  {

    Employeeattendenceretrieve(); 
}
elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['Allemployeedetails']))  {

     Fullemployeedetails();
}
elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['leaveshistory']))  {

    Getleavehistory();
}
elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['EmployeeStatus']))  {

    Employeestatus();
}
 }

 else {
    // API key is invalid, return an error response
    http_response_code(401); // Unauthorized
    echo json_encode(array("error" => "Invalid API key"));
}

function validateAndSanitizeInput($input) {
    // Check if the input exists in the $_POST array
    if(isset($_POST[$input])) {
        // Sanitize the input by removing HTML tags and special characters
        return htmlspecialchars(strip_tags($_POST[$input]));
    } else {
        return null;
    }
}


 function Signup() {
    global $conn;


    $Username = validateAndSanitizeInput('Username');
    $Password = validateAndSanitizeInput('Password');
    $Email = validateAndSanitizeInput('Email');
    $userid = validateAndSanitizeInput('Userid');
    $PhoneNo = validateAndSanitizeInput('PhoneNo');
    $Userrole = validateAndSanitizeInput('Userrole');
    // Prepare the SQL statement with placeholders
    $sql = "INSERT INTO signup(Username, Password, Email, Userid, PhoneNo, Userrole) 
            VALUES (?, ?, ?, ?, ?, ?)";

    // Prepare the statement
    $stmt = mysqli_prepare($conn, $sql);

    // Bind parameters to the statement
    mysqli_stmt_bind_param($stmt, "ssssss", $Username, $Password, $Email, $userid, $PhoneNo, $Userrole);

    // Execute the statement
    if (mysqli_stmt_execute($stmt)) {
        echo json_encode(array(
            "status" => "success",
            "message" => "Data has been submitted successfully"
        ));
    } else {
        echo json_encode(array(
            "status" => "error",
            "message" => "Error: " . mysqli_stmt_error($stmt)
        ));
    }

    // Close the statement
    mysqli_stmt_close($stmt);
}


function Login() {

   $secretKey = "irCEcuQzsOd3qBPQgi2SU7VlmqMKm1JG";
    global $conn;
    $username = $_POST["userid"];
    $password = $_POST["password"];
    // Use prepared statements to prevent SQL injection
    $stmt = $conn->prepare("SELECT * FROM signup WHERE Userid = ? AND Password = ?");
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        // User credentials are valid, generate JWT
        $issuedAt = time();
        $expirationTime = $issuedAt + 3600; // 1 hour (adjust as needed)
        $tokenPayload = array(
            'username' => $username,
            'iat' => $issuedAt,
            'exp' => $expirationTime
        );
        $token = JWT::encode($tokenPayload, $secretKey, 'HS256');

        // Fetch user details including user_role
        $row = $result->fetch_assoc();
        $userRole = $row['Userrole'];
        $username = $row['Username'];
        $email = $row['Email'];

        // Send a single JSON object as the response
        $responseJson = array(
            'status' => 'success',
            'token' => $token,
            'username' => $username,
            'email' => $email,
            'user_role' => $userRole
        );
        echo json_encode($responseJson);
    } else {
        // Invalid credentials, send error message
        http_response_code(401);
        echo json_encode(array('status' => 'error', 'message' => 'Authentication failed'));
    }

    // Close the prepared statement
    $stmt->close();
    

}

function Sentotp() {
global $conn;  

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();


$accountSid = getenv('TWILIO_ACCOUNT_SID');
$authToken = getenv('TWILIO_AUTH_TOKEN');
$twilioNumber = getenv('TWILIO_NUMBER');


 $mobile = isset($_POST["mobile"]) ? $_POST["mobile"] : null;
 $enteredOtp = isset($_POST["entered_otp"]) ? $_POST["entered_otp"] : null;

  // Log the received POST data
  // Perform any additional validation or data processing as needed
      // Generate a random 4-digit OTP
       $otp = rand(1000, 9999) ;

      // Save the OTP in the database for validation
      $sql = "UPDATE `signup` SET `otp` = '$otp' WHERE `PhoneNo` = '$mobile'";
      if (mysqli_query($conn, $sql)) {
          // Send the OTP using Twilio
          try {
              $twilio = new Client($accountSid, $authToken);
              $message = $twilio->messages
                  ->create(
                      $mobile, // To number
                      array(
                          "from" => $twilioNumber,
                          "body" => "Your OTP is: $otp"
                      )
                  );

              // Check if the message was sent successfully
              if ($message->sid) {
                  echo json_encode(array(
                      "status" => "success",
                      "message" => "OTP sent successfully",
                      "otp" => $otp
                  ));
              } else {
                  echo json_encode(array(
                      "status" => "error",
                      "message" => "Error sending OTP. Please try again."
                  ));
              }
          } catch (Exception $e) {
              echo json_encode(array(
                  "status" => "error",
                  "message" => "Error sending OTP: " . $e->getMessage()
              ));
          }
      } else {
          echo json_encode(array(
              "status" => "error",
              "message" => "Error updating OTP: " . mysqli_error($conn)
          ));
      }


}

function Validateotp() {

    global $conn;

    $enteredOtp = isset($_POST["entered_otp"]) ? $_POST["entered_otp"] : null;

    $mobile = isset($_POST["mobile"]) ? $_POST["mobile"] : null;

    $sql = "SELECT `otp` FROM `signup` WHERE `PhoneNo` = '$mobile'";
    $result = mysqli_query($conn, $sql);

    if ($result) {
        $row = mysqli_fetch_assoc($result);
        $savedOtp = $row['otp'];

        // Compare the entered OTP with the saved OTP
        if ($enteredOtp == $savedOtp) {
            echo json_encode(array(
                "status" => "success",
                "message" => "OTP validation successful"
            ));
        } else {
            echo json_encode(array(
                "status" => "error",
                "message" => "Invalid OTP"
            ));
        }
    } else {
        echo json_encode(array(
            "status" => "error",
            "message" => "Error: " . mysqli_error($conn)
        ));
    }


}
function ResetPassword() {
    global $conn ;

$desiredUsername = $_POST["phoneno"];
$newPassword = $_POST["new_password"];
$confirmPassword = $_POST["confirm_password"];

    // Perform any additional validation or data processing as needed

    // Check if passwords match
    if ($newPassword != $confirmPassword) {
        echo json_encode(array(
            "status" => "error",
            "message" => "Passwords do not match"
        ));
        exit();
    }

    // Update the user's password in the database
    $sql = "UPDATE `signUp` SET `Password` = '$newPassword' WHERE `PhoneNo` = '$desiredUsername'";
    
    if (mysqli_query($conn, $sql)) {
        echo json_encode(array(
            "status" => "success",
            "message" => "Password reset successful"
        ));
    } else {
        echo json_encode(array(
            "status" => "error",
            "message" => "Error updating password: " . mysqli_error($conn)
        ));
    }

}

function processLeaveRequest(){

    global $conn ;
    // Retrieve data
    $result = mysqli_query($conn, "SELECT * FROM leave_applications WHERE status = -1 ");
    $data = array();

    while ($row = mysqli_fetch_assoc($result)) {
        $data[] = $row;
    }

    echo json_encode(array(
        "status" => "success",
        "data" => $data
    ));
}

function DailyActicitySubmitting() {

    global $conn ;

    $Project = $_POST["Project"];
    $PhysicalLocation = $_POST["PhysicalLocation"];
    $State = $_POST["State"];
    $NoOfHoursWorked = $_POST["NoOfHoursWorked"];
    $MeetingId = $_POST["MeetingId"];
    $Type = $_POST["Type"];
    $Calendar = $_POST["Calendar"];
    $InTime = $_POST["InTime"];
    $OutTime = $_POST["OutTime"];
    $Userrole = $_POST["Userrole"];
    error_log("Received Userrole: " . $Userrole);
    
    // Perform any additional validation or data processing as needed

    $sql = "INSERT INTO attendance(Project, PhysicalLocation, State, NoOfHoursWorked, MeetingId, Type, Calendar, InTime, OutTime,  Userrole) 
            VALUES ('$Project', '$PhysicalLocation', '$State', '$NoOfHoursWorked', '$MeetingId', '$Type', '$Calendar', '$InTime', '$OutTime', '$Userrole')";
            
    if (mysqli_query($conn, $sql)) {
        echo json_encode(array(
            "status" => "success",
            "message" => "Data has been submitted successfully"
        ));
    } else {
        echo json_encode(array(
            "status" => "error",
            "message" => "Error: " . mysqli_error($conn)
        ));
    }

}

function sendmailandstoringDatabse(){
    global $conn;

    $name = $_POST["name"];
    $fromDate = date('Y-m-d', strtotime($_POST["from_date"]));
    $toDate = date('Y-m-d', strtotime($_POST["to_date"]));
    $days=$_POST["dayss"];
    $reason = $_POST["reason"];
    $userId  =  $_POST["userId"];

    function storeDataInDatabase($conn, $name, $fromDate, $toDate,$days, $reason, $userId) {
        global $conn ;
        $sql = "INSERT INTO leave_applications (name, from_date, to_date, days, reason,userId) 
                VALUES ('$name', '$fromDate', '$toDate','$days', '$reason', '$userId')";
    
        if (mysqli_query($conn, $sql)) {
            return true;
        } else {
            return false;
        }
    }
    function sendEmail($to, $subject, $message ,$name) {
        $mail = new PHPMailer(true);
    
        try {
            $mail->isSMTP();
            $mail->Host       = 'smtp.gmail.com';
            $mail->SMTPAuth   = true;
            $mail->Username   = 'sailaxminarayana465@gmail.com'; // Your Gmail address
            $mail->Password   = 'boarfgumujmdudek'; // Your Gmail password
            $mail->SMTPSecure = 'tls'; // Use 'tls' or 'ssl'
            $mail->Port       = 587; // Use 587 for TLS or 465 for SSL
    
            $mail->setFrom('sailaxminarayana465@gmail.com', $name);  
            $mail->addAddress($to);
    
            $mail->isHTML(true); // Set to true if you want to send HTML emails
            $mail->Subject = $subject;
            $mail->Body    = $message;
    
            $mail->send();
            return true;
        } catch (Exception $e) {
            return false;
        }
    }
    
        // Perform any additional validation or data processing as neede
        // Store data in the database
        $databaseSuccess = storeDataInDatabase($conn, $name, $fromDate, $toDate,$days, $reason, $userId);
    
        // Send email if data is stored in the database successfully
        if ($databaseSuccess) {
            $to = 'sailaxminarayana10@gmail.com';
            $subject = 'Leave Application - ' . $name; // Dynamic subject
    
            $emailMessage = "
            <html>
            <head>
            <style>
              th {
                font-weight: bold;
              }
              .highlight {
                background-color: #FFFF00; /* Yellow background */
                font-weight: bold;
              }
              header {
                font-weight: bold;
              }
    
            </style>
            </head>
            <body>
              <header> LEAVE APPLICATION </header>
              <table>
                <tr>
                  <th>Employee Name:</th>
                  <td>$name</td>
                </tr>
                <tr>
                  <th>From Date:</th>
                  <td>$fromDate</td>
                </tr>
                <tr>
                  <th>To Date:</th>
                  <td>$toDate</td>
                </tr>
                <tr>
                <th>Days:</th>
                <td>$days</td>
              </tr>
                <tr>
                  <th>Reason:</th>
                  <td class='highlight'>$reason</td>
                </tr>
                <tr>
                  <th>User ID:</th>
                  <td>$userId</td>
                </tr>
              </table>
            </body>
            </html>";
    
            $emailSuccess = sendEmail($to, $subject, $emailMessage ,$name);
    
            if ($emailSuccess) {
                echo json_encode(array(
                    "status" => "success",
                    "message" => "Data has been submitted successfully, and email has been sent"
                ));
            } else {
                echo json_encode(array(
                    "status" => "error",
                    "message" => "Data has been submitted successfully, but email could not be sent"
                ));
            }
        } else {
            echo json_encode(array(
                "status" => "error",
                "message" => "Error: " . mysqli_error($conn)
            ));
        }
}

function Employeeattendenceretrieve() {
 global $conn ;
 
$month = isset($_GET['month']) ? $_GET['month'] : date('n'); // Default to current month
$year = isset($_GET['year']) ? $_GET['year'] : date('Y'); // Default to current year
$userRole = isset($_GET['userRole']) ? $_GET['userRole'] : 'default'; // Default user role


// Perform SELECT query to retrieve data for the specified month, year, and user role
$sql = "SELECT * FROM attendance WHERE YEAR(Calendar) = $year AND MONTH(Calendar) = $month AND UserRole = '$userRole'";
$result = mysqli_query($conn, $sql);
if ($result) {
    $response = array();

    // Output data of each row
    while ($row = mysqli_fetch_assoc($result)) {
        $response[] = $row;
    }

    // Encode the response as JSON and output
    echo json_encode($response);
} else {
    // Provide a consistent JSON response even in case of an error
    echo json_encode(array("error" => "Error fetching data from the database"));
}

}

function submitReason(){

global $conn;    

$reason = isset($_POST["reason"]) ? $_POST["reason"] : '';
$userid = isset($_POST["userid"]) ? $_POST["userid"] : '';
$status = isset($_POST["status"]) ? $_POST["status"] : '';
$fromdate = isset($_POST["fromdate"]) ? $_POST["fromdate"] : '';
$todate  = isset($_POST["todate"]) ? $_POST["todate"] : '';
$name = isset($_POST["name"]) ? $_POST["name"] : '';

// Use a prepared statement to prevent SQL injection
$stmt = mysqli_prepare($conn, "INSERT INTO reason (reason, userid, status,fromdate,todate,name) VALUES (?, ?, ?,?,?,?)");
mysqli_stmt_bind_param($stmt, "siisss", $reason, $userid, $status,$fromdate,$todate,$name);

// Execute the statement
if (mysqli_stmt_execute($stmt)) {
    // Insertion into 'reason' table successful, now delete the row from 'leave_applications
       $updateQuery = "UPDATE leave_applications SET status = $status WHERE userid = '$userid'";
       mysqli_query($conn, $updateQuery);
    } 
else {
    echo json_encode(array(
        "status" => "error",
        "message" => "Error inserting reason into the database: " . mysqli_error($conn)
    ));
}

// Close the statement
mysqli_stmt_close($stmt);

}


function InsertID() {
  global $conn ;
 
        if (isset($_POST["Userid"]) && isset($_POST["Username"])) { // Modified to accept both username and userid
            $userid = $_POST["Userid"];
            $username = $_POST["Username"]; // Added to accept username
    
            $sql = "INSERT INTO admin (Userid, Username) VALUES ('$userid', '$username')"; // Modified to insert both userid and username
    
            if ($conn->query($sql) === TRUE) {
                $response["status"] = "success";
                $response["message"] = "Data inserted successfully";
            } else {
                $response["status"] = "error";
                $response["message"] = "Error inserting data: " . $conn->error;
            }
    
            echo json_encode($response);
        }
    

}
function Delete() {
global $conn;
if (isset($_POST["Userid"])) {
    $useridToDelete = $_POST["Userid"];

    $sql = "DELETE FROM admin WHERE Userid = '$useridToDelete'";

    if ($conn->query($sql) === TRUE) {
        $response["status"] = "success";
        $response["message"] = "Data deleted successfully";
    } else {
        $response["status"] = "error";
        $response["message"] = "Error deleting data: " . $conn->error;
    }

    echo json_encode($response);
}
}

function Fullemployeedetails() {
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
    global $conn;

    $result = mysqli_query($conn, "SELECT * FROM signup");
    $data = array();

    while ($row = mysqli_fetch_assoc($result)) {
        $data[] = $row;
    }

    echo json_encode(array(
        "status" => "success",
        "data" => $data
    ));
}

function Getleavehistory() {
   global $conn ;
   if ($conn->connect_error) {
    // Return error response as JSON
    $response = array("error" => "Connection failed: " . $conn->connect_error);
    header('Content-Type: application/json');
    echo json_encode($response);
    exit; // Terminate script execution
}

// Handle API request
    // Retrieve parameters
    $startDate = isset($_GET['fromdate']) ? $_GET['fromdate'] : null;
    $endDate =isset($_GET['todate']) ? $_GET['todate'] : null;
    $userId = isset($_GET['Userid']) ? $_GET['Userid'] : null;
    $status = isset($_GET['status']) ? $_GET['status'] : null;
     // Set default values for date parameters if not provided
     if ($startDate === null || $startDate === '') {
        // Set default start date
        $startDate = '1970-01-01';
    }
    
    if ($endDate === null || $endDate === '') {
        // Set default end date
        $endDate = '2100-12-31';
    }

    
    // Construct SQL query
    $sql = "SELECT * FROM reason WHERE";

    // Add user ID condition if provided
if ($userId !== null && $userId !== '') {
    $sql .= " Userid = '$userId'";
}

// Add status condition if provided
// Add status condition if provided
if ($status !== null && $status !== '') {
    // Add AND if there's a user ID condition
    if ($userId !== null && $userId !== '') {
        $sql .= " AND";
    }
    // Convert status string to the corresponding integer value
    if ($status === 'Rejected') {
        $statusValue = 0;
    } else if ($status === 'Approved') {
        $statusValue = 1;
    }
    $sql .= " status = $statusValue";
}

// Add date conditions if dates are provided
if ($startDate !== '' && $endDate !== '') {
    // Add AND if there's a previous condition
    if ($userId !== null && $userId !== '' || ($status !== null && $status !== '')) {
        $sql .= " AND";
    }
    $sql .= " ((fromdate BETWEEN '$startDate' AND '$endDate') OR (todate BETWEEN '$startDate' AND '$endDate'))";
}


    // Execute SQL query
    $result = $conn->query($sql);

    // Process query result
    if ($result === false) {
        // Return error response as JSON
        $response = array("error" => "Error executing query: " . $conn->error);
        header('Content-Type: application/json');
        echo json_encode($response);
        exit; // Terminate script execution
    }

    $leaveHistory = [];
    if ($result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            $leaveHistory[] = $row;
        }
    }

    // Return leave history as JSON response
    header('Content-Type: application/json');
    echo json_encode($leaveHistory);


}
function Employeestatus(){
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
        global $conn ;
        // Retrieve data based on user ID
        $userid = $_GET['userid']; // Assuming the user ID is passed as a parameter
    
        // Check if Userid matches with the user ID from the useridpassing class
        $query = "SELECT reason, status, timestamp1 ,fromdate ,todate FROM reason WHERE Userid = '$userid'";
        $result = mysqli_query($conn, $query);
    
        if (!$result) {
            echo json_encode(array(
                "status" => "error",
                "message" => "Error executing SELECT query: " . mysqli_error($conn)
            ));
            exit();
        }
    
        // Check if any rows are returned
        if (mysqli_num_rows($result) > 0) {
            $data = array();
    
            while ($row = mysqli_fetch_assoc($result)) {
                $data[] = $row;
            }
    
            echo json_encode(array(
                "status" => "success",
                "data" => $data
            ));
        } else {
            echo json_encode(array(
                "status" => "error",
                "message" => "No data found for the provided user ID"
            ));
        }
}


$conn->close();
?>

