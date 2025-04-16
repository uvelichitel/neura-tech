package main

import (
	"bytes"
	"context"
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

var (
	layout           = "060102150405"
	notificationURL  string
	hmacSecret       string
	terminalPassword string
	terminalKey      string
	connStr          string
	signalURL        string
	signalToken      string
	acquiringURL     string
	logFile          string
	logWriter        io.Writer
	logger           *log.Logger
	db               Store
)

func init() {
	var (
		ok  bool
		err error
	)
	logFile, ok = os.LookupEnv("LOG_FILE")
	if !ok {
		print("LOG_FILE not set")
	}
	logWriter, err = os.OpenFile(logFile, os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		print(err.Error())
	}
	logger = log.New(logWriter, "neura", log.LstdFlags)

	notificationURL, ok = os.LookupEnv("NOTIFICATION_URL")
	if !ok {
		logger.Fatal("NOTIFICATION_URL not set")
	}
	hmacSecret, ok = os.LookupEnv("HMACSECRET")
	if !ok {
		logger.Fatal("HMACSECRET not set")
	}
	terminalPassword, ok = os.LookupEnv("TERMINAL_PASSWORD")
	if !ok {
		logger.Fatal("TERMINAL_PASSWORD not set")
	}
	terminalKey, ok = os.LookupEnv("TERMINAL_KEY")
	if !ok {
		logger.Fatal("TERMINAL_KEY not set")
	}
	connStr, ok = os.LookupEnv("CONN_STR")
	if !ok {
		logger.Fatal("CONN_STR not set")
	}
	signalURL, ok = os.LookupEnv("SIGNAL_URL")
	if !ok {
		logger.Fatal("SIGNAL_URL not set")
	}
	signalToken, ok = os.LookupEnv("SIGNAL_TOKEN")
	if !ok {
		logger.Fatal("SIGNAL_TOKEN not set")
	}
	acquiringURL, ok = os.LookupEnv("ACQUIRING_URL")
	if !ok {
		logger.Fatal("ACQUIRING_URL not set")
	}
}

type Store struct {
	stmts map[string]*sql.Stmt
	*sql.DB
}

type InitOrder struct {
	Amount      int64  `json:"Amount"`
	Description string `json:"Description"`
}

type InitOrderResponce struct {
	PaymentURL string `json:"PaymentURL"`
	Details    string `json:"Details"`
}

type DATA struct {
	OperationInitiatorType string `json:"OperationInitiatorType,omitempty"`
	CustomerID             string `json:"CustomerID,omitempty"`
}

type InitPayment struct {
	TerminalKey     string `json:"TerminalKey,omitempty"`
	Amount          int64  `json:"Amount,omitempty"`
	OrderId         string `json:"OrderId,omitempty"`
	Token           string `json:"Token,omitempty"`
	Description     string `json:"Description,omitempty"`
	CustomerKey     string `json:"CustomerKey,omitempty"`
	Recurrent       string `json:"Recurrent,omitempty"`
	PayType         string `json:"PayType,omitempty"`
	Language        string `json:"Language,omitempty"`
	NotificationURL string `json:"NotificationURL,omitempty"`
	SuccessURL      string `json:"SuccessURL,omitempty"`
	FailURL         string `json:"FailURL,omitempty"`
	RedirectDueDate string `json:"RedirectDueDate,omitempty"`
	DATA
	//Receipt Receipt `json:"Receipt ,omitempty"`
}

type InitResponse struct {
	TerminalKey string `json:"TerminalKey"`
	Amount      int64  `json:"Amount"`
	OrderId     string `json:"OrderId"`
	Success     bool   `json:"Success"`
	Status      string `json:"Status"`
	PaymentId   string `json:"PrsaymentId"`
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

func Connect(connStr string) (*sql.DB, error) {
	db, err := sql.Open("pgx", connStr)

	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	log.Println("Successfully connected to database and pinged it")
	return db, nil
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
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("Поддельный ключ. Попробуйте авторизоваться заново.")
	}
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
	userID, err := strconv.ParseInt(notification.OrderId[:13], 10, 64)
	if err != nil {
		// TODO
	}
	p := new(PaymentSignal)
	p.Amount = notification.Amount / 100
	p.Status = notification.Status
	p.Payment_id = notification.PaymentId.String()
	p.User_id = userID
	if err != nil {
		// TODO
	}
	p.Sign()
	err = Signal(p)
	if err != nil {
		// TODO recall, context with timeout, return, place in queue
	}
	if notification.Status != "CONFIRMED" {
		err = db.UpdateStatus(notification)
	} else {
		err = db.Persist(notification)
	}
	if err != nil {
		// TODO
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *PaymentSignal) Sign() {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(hmacSecret))
	// Write Data to it
	amount := strconv.FormatInt(s.Amount, 10)
	userID := strconv.FormatInt(s.User_id, 10)
	data := s.Payment_id + userID + amount + s.Status
	h.Write([]byte(data))
	// Get result and encode as hexadecimal string
	s.Signature = hex.EncodeToString(h.Sum(nil))
}

func Signal(s *PaymentSignal) error {
	json, err := json.Marshal(s)
	if err != nil {
		return err
	}
	body := bytes.NewBuffer(json)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", signalURL, body)
	if err != nil {
		return err
	}
	//	var bearer = "Bearer " + signalToken
	//	req.Header.Set("Authorization", bearer)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New("StatusCode " + strconv.FormatInt(int64(resp.StatusCode), 10))
	}
	defer resp.Body.Close()
	return nil
}

func EncodeOrderId(u string) string {
	t := time.Now().Format(layout)
	return u + "#" + t
}

func DecodeOrderId(id string) (string, time.Time) {
	u := id[:len(id)-13]
	t, err := time.Parse(layout, id[len(id)-12:])
	if err != nil {
		t = time.Now()
	}
	return u, t
}

func InitiatePayment(o *InitOrder, u string) (string, string) {
	o.Amount *= 100
	orderId := EncodeOrderId(u)
	req := &InitPayment{
		TerminalKey:     terminalKey,
		Amount:          o.Amount,
		OrderId:         orderId,
		Description:     o.Description,
		CustomerKey:     u,
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
		return "", err.Error()
	}
	cont := bytes.NewReader(jsn)
	resp, err := http.Post("https://securepay.tinkoff.ru/v2/Init", "application/json", cont)
	// resp, err := http.Post("https://rest-api-test.tinkoff.ru/v2/init", "application/json", bytes.NewReader(jsn))
	if err != nil {
		return "", err.Error()
	}
	if resp.StatusCode != 200 {
		return "", "Internal server error"
	}
	defer resp.Body.Close()
	rspns := new(InitResponse)
	err = json.NewDecoder(resp.Body).Decode(rspns)
	if err != nil {
		return "", err.Error()
	}
	if rspns.ErrorCode != "0" {
		return "", rspns.Message
	}
	return rspns.PaymentURL, ""
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
	resp := new(InitOrderResponce)
	resp.PaymentURL, resp.Details = InitiatePayment(initOrder, user)
	if resp.PaymentURL == "" || resp.Details != "" {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	enc := json.NewEncoder(w)
	err = enc.Encode(resp)
	if err != nil {
		logger.Println(err.Error())
	}
}

func MakeStore() (db Store, err error) {
	if db.DB, err = Connect(connStr); err != nil {
		return
	}
	db.stmts = make(map[string]*sql.Stmt)
	return db, nil
}

func (s Store) Init() (err error) {
	s.stmts["updateStatus"], err = s.Prepare("UPDATE payments SET status = $1 WHERE paymentid = $2")
	if err != nil {
		return
	}
	db.stmts["payment"], err = s.Prepare("INSERT INTO payments (paymentid, status, date, orderid, amount, customerkey) VALUES ($1, $2, $3, $4, $5, $6)")
	if err != nil {
		return
	}
	db.stmts["remove"], err = s.Prepare("DELETE FROM payments WHERE paymentid = $1")
	if err != nil {
		return
	}
	return nil
}

func (s Store) Cleanup() {
	for _, v := range s.stmts {
		v.Close()
	}
	s.Close()
}

func (s Store) Persist(n *Notification) error {
	customerKey, time := DecodeOrderId(n.OrderId)
	_, err := s.stmts["payment"].Exec(n.PaymentId, n.Status, time, n.OrderId, n.Amount, customerKey)
	return err
}

func (s Store) UpdateStatus(n *Notification) error {
	_, err := s.stmts["updateStatus"].Exec(n.Status, n.PaymentId)
	return err
}

func (s Store) Remove(n Notification) error {
	_, err := s.stmts["remove"].Exec(n.PaymentId)
	return err
}

func main() {
	l, err := net.Listen("tcp", acquiringURL)
	if err != nil {
		log.Fatal(err)
	}
	db, err = MakeStore()
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/payment", Pay)
	mux.HandleFunc("/notification", GetNotification)
	print("Listen on: ", acquiringURL)
	logger.Fatal(http.Serve(l, mux))
}

//	NEW
//	CANCELED
//	AUTHORIZED
//	PARTIAL_REVERSED
//	REVERSED
//	CONFIRMED
//	PARTIAL_REFUNDED
//	REFUNDED
