package com.sample.otp;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;



public class MainActivity extends AppCompatActivity {

    @Override


    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        Thread t =new Thread()
        { @Override
            public void run(){
                try{
                    while(!isInterrupted()){
                        Thread.sleep(100);
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                TextView tdate=(TextView)findViewById(R.id.etInput);
                                long date =System.currentTimeMillis();
                                SimpleDateFormat sdf= new SimpleDateFormat("dd MMM yyyy\nhh-mm-ss a");
                                String dateString =sdf.format(date);
                                tdate.setText(dateString);
                            }
                        });
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
        }
        };
t.start();

    }

    public void genrateOtp(View view)
    {

        String seed = "2113221";

        long T0 = 0;
        long X = 60;

        long time =System.currentTimeMillis()/1000;
        System.out.println(Calendar.getInstance().getTime().getSeconds());
        //(int) (new Date().getTime()/1000);

        long testTime[] = {time};

        String steps = "0";

        try{
            System.out.println(
                    "+--------------+----" +
                            "-------------+");
            System.out.println(
                    "|  Time(secs)  | " +
                            " TOTP  | Mode   |");
            System.out.println(
                    "+--------------+----" +
                            "-------------+");

            for(int i=0; i<testTime.length; i++) {
                long T = (testTime[i] - T0)/X;
                steps = Long.toHexString(T).toUpperCase();
                while(steps.length() < 16) steps = "0" + steps;
                String fmtTime = String.format("%1$-10s", testTime[i]);

                System.out.print("|  " + fmtTime +
                        "  |");
                System.out.println(generateTOTP(seed, steps, "6",
                        "HmacSHA1") + "  | SHA1   |");
                System.out.print("|  " + fmtTime   +
                        "  |");
                System.out.println(generateTOTP(seed, steps, "6",
                        "HmacSHA256") + "  | SHA256 |");


                String otp=generateTOTP(seed, steps, "6",
                        "HmacSHA256");
                otp=otp.substring(0,3)+"  "+otp.substring(3);
                TextView otptext=(TextView)findViewById(R.id.etOutput);
                otptext.setText(otp);

                System.out.print("|  " + fmtTime +
                        "  |");
                System.out.println(generateTOTP(seed, steps, "6",
                        "HmacSHA512") + "  | SHA512 |");

                System.out.println(
                        "+--------------+-----------------+");
            }




        }catch (final Exception e){
            System.out.println("Error : " + e);
        }

    }


    private static byte[] hmac_sha1(String crypto, byte[] keyBytes,
                                    byte[] text)
    {
        try {
            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey =
                    new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }

    private static byte[] hexStr2Bytes(String hex){
        // Adding one byte to get the right conversion
        // values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex,16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length ; i++)
            ret[i] = bArray[i+1];
        return ret;
    }
    private static final int[] DIGITS_POWER
            // 0 1  2   3    4     5      6       7        8
            = {1,10,100,1000,10000,100000,1000000,10000000,100000000 };
    public static String generateTOTP(String key,
                                      String time,
                                      String returnDigits)
    {
        return generateTOTP(key, time, returnDigits, "HmacSHA1");
    }

    public static String generateTOTP256(String key,
                                         String time,
                                         String returnDigits)
    {
        return generateTOTP(key, time, returnDigits, "HmacSHA256");
    }
    public static String generateTOTP512(String key,
                                         String time,
                                         String returnDigits)
    {
        return generateTOTP(key, time, returnDigits, "HmacSHA512");
    }
    private static String generateTOTP(String key,
                                       String time,
                                       String returnDigits,
                                       String crypto)
    {
        int codeDigits = Integer.decode(returnDigits).intValue();
        String result = null;
        byte[] hash;

        // Using the counter
        // First 8 bytes are for the movingFactor
        // Complaint with base RFC 4226 (HOTP)
        while(time.length() < 16 )
            time = "0" + time;

        // Get the HEX in a Byte[]
        byte[] msg = hexStr2Bytes(time);

        // Adding one byte to get the right conversion
        byte[] k = hexStr2Bytes(key);

        hash = hmac_sha1(crypto, k, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary =
                ((hash[offset] & 0x7f) << 24) |
                        ((hash[offset + 1] & 0xff) << 16) |
                        ((hash[offset + 2] & 0xff) << 8) |
                        (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = Integer.toString(otp);
        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }

}
