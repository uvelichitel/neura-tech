package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Status int8

const (
	NEW Status = iota + 1
	CANCELED
	AUTHORIZED
	PARTIAL_REVERSED
	REVERSED
	CONFIRMED
	PARTIAL_REFUNDED
	REFUNDED
)

var (
	notificationURL  = os.Getenv("NOTIFICATION_URL")
	hmacSecret       = []byte(os.Getenv("HMACSECRET")) // TODO
	terminalPassword = os.Getenv("TERMINAL_PASSWORD")
	terminalKey      = os.Getenv("TERMINAL_KEY")
	connStr          = os.Getenv("CONN_STR")
	signalURL        = os.Getenv("SIGNAL_URL")
	db               *sql.DB
	stmts            = make(map[string]*sql.Stmt)
)
var logWriter io.Writer
var logger *log.Logger = log.New(logWriter, "neura", log.LstdFlags)

// Tbank
type InitOrder struct {
	Amount      int64  `json:"Amount"`
	Description string `json:"Description"`
}

type Order struct {
	InitOrder
	OrderId string `json:"OrderId"`
	//	Amount      int64     `json:"Amount"`
	//	Description string    `json:"Description"`
	CustomerKey string    `json:"CustomerKey"` //UserID
	Date        time.Time // TODO
}

type DATA struct {
	OperationInitiatorType string `json:"OperationInitiatorType,omitempty"`
	CustomerID             string `json:"CustomerID,omitempty"`
}

type Payment struct {
	PaymentId string `json:"PaymentId,omitempty"`
	Order
	Status    string `json:"Status"`
	Success   bool   `json:"Success"`
	Recurrent string `json:"Recurrent,omitempty"`
	PayType   string `json:"PayType,omitempty"`
	DATA      `json:"DATA"`
	Date      time.Time
}

type InitPayment struct {
	Payment
	TerminalKey     string `json:"TerminalKey,omitempty"`
	Token           string `json:"Token,omitempty"`
	Language        string `json:"Language,omitempty"`
	NotificationURL string `json:"NotificationURL,omitempty"`
	SuccessURL      string `json:"SuccessURL,omitempty"`
	FailURL         string `json:"FailURL,omitempty"`
	RedirectDueDate string `json:"RedirectDueDate,omitempty"`
	//Receipt Receipt `json:"Receipt ,omitempty"`
}

type InitResponse struct {
	TerminalKey string `json:"TerminalKey"`
	Amount      int64  `json:"Amount"`
	OrderId     string `json:"OrderId"`
	Success     bool   `json:"Success"`
	Status      string `json:"Status"`
	PaymentId   string `json:"PaymentId"`
	ErrorCode   string `json:"ErrorCode"`
	PaymentURL  string `json:"PaymentURL"`
	Message     string `json:"Message"`
	Details     string `json:"Details"`
}

type Notification struct {
	TerminalKey string      `json:"TerminalKey"`
	Amount      int64       `json:"Amount"`
	OrderId     string      `json:"OrderId"`
	Success     bool        `json:"Success"`
	Status      string      `json:"Status"`
	PaymentId   json.Number `json:"PaymentId"`
	ErrorCode   string      `json:"ErrorCode"`
	Message     string      `json:"Message"`
	Details     string      `json:"Details"`
	RebillId    uint64      `json:"RebillId"`
	CardId      uint64      `json:"CardId"`
	Pan         string      `json:"Pan"`
	ExpDate     string      `json:"ExpDate"`
	Token       string      `json:"Token"`
	DATA        `json:"DATA"`
	Date        time.Time
}

type CanselRequest struct {
	TerminalKey       string      `json:"TerminalKey,omitempty"`
	PaymentId         json.Number `json:"PaymentId,omitempty"`
	Token             string      `jsIPon:"Token,omitempty"`
	IP                string      `json:"IP,omitempty"`
	Amount            int64       `json:"Amount,omitempty"`
	ExternalRequestId string      `json:"ExternalRequestId,omitempty"`
}

type CanselResponse struct { // TODO
	TerminalKey       string `json:"TerminalKey"`
	OrderId           string `json:"OrderId"`
	Success           bool   `json:"Success"`
	OriginalAmount    int64  `json:"OriginalAmount"`
	NewAmount         int64  `json:"NewAmount"`
	PaymentId         string `json:"PaymentId"`
	ErrorCode         string `json:"ErrorCode"`
	Message           string `json:"Message"`
	Details           string `json:"Details"`
	ExternalRequestId string `json:"ExternalRequestId"`
}

type PaymentSignal struct {
	Payment_id string `json:"payment_id"`
	User_id    int64  `json:"user_id"`
	Amount     int64  `json:"amount"`
	Status     string `json:"status"`
	Signature  string `json:"signature"`
}

type sqlDB struct {
	stmts map[string]*sql.Stmt
	*sql.DB
}

//func ConnectionString() string {
//	connStr, status := os.LookupEnv("CONN_STR")
//	if !status {
//		log.Fatalln("Missing environment variable CONN_STR")
//	}
//
//	return connStr
//}

func Connect() *sql.DB {
	//connStr := ConnectionString()

	db, err := sql.Open("pgx", connStr)

	if err != nil {
		log.Fatalf("Unable to connect to database because %s", err)
	}

	if err = db.Ping(); err != nil {

		log.Fatalf("Cannot ping database because %s", err)

	}

	log.Println("Successfully connected to database and pinged it")
	return db
}

func (i *InitPayment) CalcToken() {
	//	str := strconv.FormatUint(i.Amount, 10) + i.CustomerKey + i.Description + i.FailURL + i.Language + i.NotificationURL + i.OrderId + TerminalPassword + i.PayType + i.Recurrent + i.RedirectDueDate + i.SuccessURL + i.TerminalKey
	str := strconv.FormatInt(i.Amount, 10) + i.CustomerKey + i.Description + i.Language + i.NotificationURL + i.OrderId + terminalPassword + i.TerminalKey
	sha := sha256.Sum256([]byte(str))
	token := hex.EncodeToString(sha[:])
	i.Token = token
}

func IsValidToken(tokenstring string) (string, error) { // TODO if to validate
	token, err := jwt.Parse(tokenstring, func(token *jwt.Token) (any, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Плохо подписан ключ. Попробуйте авторизоваться заново.")
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSecret, nil
	})
	//if err != nil {
	//	return "", err
	//}
	//if !token.Valid {
	//	return "", errors.New("Плохой ключ. Попробуйте авторизоваться заново.")
	//}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("Поддельный ключ. Попробуйте авторизоваться заново.")
	}
	//end, err := claims.GetExpirationTime()
	//if (err != nil) || end.Time.Before(time.Now()) {
	//	return "", errors.New("Ключ протух. Попробуйте авторизоваться заново.")
	//}
	customerKey, err := claims.GetSubject()
	if err != nil {
		return "", err
	}
	return customerKey, nil
}

func GetNotification(w http.ResponseWriter, r *http.Request) {
	notification := new(Notification)
	if err := json.NewDecoder(r.Body).Decode(notification); err != nil {
		//TODO
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
	_, err := stmts["notification"].Exec(notification.Status, notification.PaymentId)
	if err != nil {
		// TODO
	}
	if notification.Status != "CONFIRMED" {
		//TODO
	}
}

func SignSignal(secret []byte, data string) string {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, secret)
	// Write Data to it
	h.Write([]byte(data))
	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

func (p *Payment) Signal() {
	user_id, err := strconv.ParseInt(p.CustomerKey, 10, 64)
	if err != nil {
		// TODO
	}
	data := p.PaymentId + p.CustomerKey + strconv.FormatInt(p.Amount, 10) + p.Status // TODO p.Amount (100.0)
	signal := PaymentSignal{
		Payment_id: p.PaymentId,
		User_id:    user_id,
		Amount:     p.Amount,
		Status:     p.Status,
		Signature:  SignSignal(hmacSecret, data),
	}
	json, err := json.Marshal(signal)
	if err != nil {
		// TODO
	}
	body := bytes.NewBuffer(json)
	resp, err := http.Post(signalURL, "application/json", body)
	if err != nil {
		// TODO
	}
	defer resp.Body.Close()
}

func Pay(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		return
	}
	tokenString = tokenString[len("Bearer "):]
	user, err := IsValidToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	initOrder := new(InitOrder)
	err = json.NewDecoder(r.Body).Decode(initOrder)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	initOrder.Amount *= 100
	orderId := new(int64)
	err = db.QueryRow("SELECT nextval('orderid')").Scan(orderId)
	req := &InitPayment{
		TerminalKey: terminalKey,
		Payment: Payment{
			Order: Order{
				OrderId:     strconv.FormatInt(*orderId, 10),
				InitOrder:   *initOrder,
				CustomerKey: user,
			},
		},
		Language:        "ru",
		NotificationURL: notificationURL,
		//		SuccessURL:      SuccessURL,
		//		FailURL:         FailURL,
		//DATA: Data{
		//	OperationInitiatorType: "0",
		//},
	}
	req.CalcToken()
	jsn, err := json.Marshal(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	cont := bytes.NewReader(jsn)
	resp, err := http.Post("https://securepay.tinkoff.ru/v2/Init", "application/json", cont)
	// resp, err := http.Post("https://rest-api-test.tinkoff.ru/v2/init", "application/json", bytes.NewReader(jsn))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
		//TODO
	}
	if resp.StatusCode != 200 {
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte("Платеж не проходит"))
		return
		//TODO
	}
	rspns := new(InitResponse)
	err = json.NewDecoder(resp.Body).Decode(rspns)
	if err != nil {
		panic(err)
	}
	_, err = stmts["payment"].Exec(rspns.PaymentId, rspns.Status, time.Now, rspns.OrderId, rspns.Amount, req.Description, req.CustomerKey)
	if err != nil {
		// TODO
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(rspns.PaymentURL))
}

func main() {
	l, err := net.Listen("tcp", ":5000")
	if err != nil {
		print(err.Error)
	}
	db := Connect()
	stmts["notification"], err = db.Prepare("UPDATE payments SET status = $1 WHERE paymentid = $2")
	if err != nil {
		log.Fatal(err)
	}
	defer stmts["notification"].Close()
	stmts["payment"], err = db.Prepare("INSERT INTO payments (paymentid, status, date, orderid, amount, description, customerkey) VALUES ($1, $2, $3, $4, $5, $6, $7)")
	if err != nil {
		log.Fatal(err)
	}
	defer stmts["payment"].Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/payment", Pay)
	mux.HandleFunc("/notification", GetNotification)
	logger.Fatal(http.Serve(l, mux))

}

//CREATE TABLE IF NOT EXISTS employees (
//		id SERIAL PRIMARY KEY,
//		name VARCHAR(100),
//		position VARCHAR(100),
//		hire_date DATE
//	)
//
//CREATE SEQUENCE IF NOT EXISTS orderid AS BIGINT START WITH start
//
//
//SELECT nextval('orderid')
//
//db.Prepare("INSERT INTO payments (paymentid, status, recurrent, paytype, date, orderid,amount, description, customerkey, operationinitiatortype) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)")
//
//
//
