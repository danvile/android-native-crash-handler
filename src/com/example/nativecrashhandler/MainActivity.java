package com.example.nativecrashhandler;

import com.iexin.common.CrashHelper;

import android.app.Activity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;


public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        new Thread(new Runnable() {
            
            @Override
            public void run() {
                  // TODO Auto-generated method stub
                  CrashHelper.init();
                  
            }
      }).start();
    }
}
