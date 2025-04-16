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
	hmacSecret = "neura-tech"
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
	hmacSecret = "neura-tech"
	s := PaymentSignal{
		Payment_id: "payment_1235",
		Amount:     500,
		Status:     "success",
		User_id:    11,
	}
	s.Sign()
	signature := s.Signature
	want := "291e3bb97ac02cbb7c058adb55bb1f3068da297020f849f5a903b9108c9df3a7"
	got := signature
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestConnect(t *testing.T) {
	connStr := "postgres://merchant:broccoly@localhost:5433/payments"
	_, err := Connect(connStr)
	if err != nil {
		t.Error(err)
	}
	// TODO
}

func TestSignal(t *testing.T) {
	hmacSecret = "neura-tech"
	signalURL = "https://gateway.neura-tech.pro/v1/balance/webhook/payment"
	//amount := strconv.FormatFloat(s.Amount, 'f', 2, 64)
	//signalToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMSIsImV4cCI6MTc0NDQ1MzE3MiwidHlwZSI6ImFjY2VzcyJ9.uepNh2AnSEamAFDRCfeQR_Quktftq2B9zV77iejaKKI"
	s := &PaymentSignal{
		Payment_id: "payment_1235",
		Amount:     500,
		Status:     "success",
		User_id:    11,
	}
	s.Sign()
	err := Signal(s)
	if err != nil {
		t.Error(err, "\n", s.Signature)
	}
}

func TestEncoder(t *testing.T) {
	layout = "060102150405"
	u := "2"
	id := EncodeOrderId(u)
	t.Log(id)
	ug, tm := DecodeOrderId(id)
	if ug != u {
		t.Error("Mismatch userId decoding ", u, ug)
	}
	if time.Now().Day() != tm.Day() {
		t.Error("Mismatch time decoding ", tm, time.Now(), " NOW ", time.Now())
	}
}
