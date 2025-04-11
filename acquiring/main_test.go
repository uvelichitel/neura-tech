package main

import (
	"testing"
	"time"
)

func TestCalcToken(t *testing.T) {
	i := InitPayment{
		TerminalKey: "MerchantTerminalKey",
		Amount:      19200,
		Description: "Подарочная карта на 1000 рублей",
		OrderId:     "21090",
	}
	terminalPassword = "usaf8fw8fsw21g"
	i.CalcToken()
	got := i.Token
	want := "0024a00af7c350a3a67ca168ce06502aa72772456662e38696d48b56ee9c97d9"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestIsValidToken(t *testing.T) {
	hmacSecret = []byte("neura-tech")
	tokenstring := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwiZXhwIjoxNzQ0MTYwOTM0LCJ0eXBlIjoiYWNjZXNzIn0.tOhDHtrxiWMUaJcX7Bg4joEUfGShXJj7_BpLV08lTD0"
	userID, err := IsValidToken(tokenstring)
	if err != nil {
		t.Error(err.Error() + "\n")
	}
	want := "2"
	got := userID
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestSign(t *testing.T) {
	s := PaymentSignal{
		Payment_id: "payment_1234",
		Amount:     100,
		Status:     "success",
		User_id:    1,
	}
	s.Sign()
	signature := s.Signature
	want := "9ba6735dd544efcb2904a511cea8c516e2d5f8b096d7ff5a4bfc653af2c73473"
	got := signature
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestConnect(t *testing.T) {
	connStr := "postgres://merchant:broccoly@localhost:5432/payments"
	_, err := Connect(connStr)
	if err != nil {
		t.Error(err)
	}
	// TODO
}

func TestSignal(t *testing.T) {
	signalURL = "TODO"
	s := &PaymentSignal{
		Payment_id: "payment_1234",
		Amount:     100,
		Status:     "success",
		User_id:    1,
	}
	s.Sign()
	err := Signal(s)
	if err != nil {
		t.Error(err)
	}
}

func TestEncoder(t *testing.T) {
	u := "2"
	id := EncodeOrderId(u)
	ug, tm := DecodeOrderId(id)
	if ug != u {
		t.Error("Mismatch userId decoding")
	}
	if time.Now().Unix()-tm.Unix() > 100 || time.Now().Unix()-tm.Unix() < 100 {
		t.Error("Mismatch time decoding")
	}
}
