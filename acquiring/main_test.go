package main

import (
	"strconv"
	"testing"
)

func TestCalcToken(t *testing.T) {
	i := InitPayment{
		TerminalKey: "MerchantTerminalKey",
		Payment: Payment{
			Order: Order{
				InitOrder: InitOrder{
					Amount:      19200,
					Description: "Подарочная карта на 1000 рублей",
				},
				OrderId: "21090",
			},
},
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

func TestSignSignal(t *testing.T) {
	p := Payment{
		PaymentId: "payment_1234",
		Order: Order{
			InitOrder: InitOrder{
				Amount: 100,
			},
			CustomerKey: "1",
		},
		Status: "success",
	}
	data := p.PaymentId + p.CustomerKey + strconv.FormatInt(p.Amount, 10) + p.Status
	signature := SignSignal(hmacSecret, data)
// TODO
	want := "9ba6735dd544efcb2904a511cea8c516e2d5f8b096d7ff5a4bfc653af2c73473" // TODO
	got := signature
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
