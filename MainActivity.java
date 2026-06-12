package com.mufe.baeksin;

import android.os.Bundle;
import android.view.WindowManager;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // 화면 캡처 / 녹화 차단 (약점 #1의 '화면 구멍')
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
}
