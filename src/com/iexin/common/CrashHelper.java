package com.iexin.common;

import java.util.Set;

import android.util.Log;

/**
 * 底层奔溃处理
 */
public class CrashHelper {
      /**
       * 调试标签
       */
      private static final String tag = "zd-crashHelper";
      /**
       * libcrashHelper.so 是否加载成功
       */
      private static boolean nativeloaded = false;

      /**
       * 初始化 crashHelper
       */
      public static void init() {
            load_crash_library();
      }

      /**
       * 加载动态链接库(libcrashHelper)
       */
      private static void load_crash_library() {
            try {
                  System.loadLibrary("crashHelper");
                  nativeloaded = true;
            } catch (UnsatisfiedLinkError error) {
                  nativeloaded = false;
            }
      }

      // 提交本地崩溃信息
      private static void commitNativeCrash(String nativeCrash, String threadName) {
            StringBuffer buffer = new StringBuffer();
            /**
             * 添加 native 堆栈信息
             */
            if (nativeCrash != null) {
                  buffer.append("###################################################################\n");
                  buffer.append("# native crash                                                    #\n");
                  buffer.append("###################################################################\n");
                  buffer.append(nativeCrash + "\n");
            }
            /**
             * 添加 java 堆栈信息
             */
            if (threadName != null) {
                  // 取得 native 崩溃对应的 java 线程
                  Set<Thread> threads = Thread.getAllStackTraces().keySet();
                  Thread javaThread = null;
                  for (Thread thread : threads) {
                        if (thread.getName().equals(threadName)) {
                              javaThread = thread;
                              break;
                        }
                  }
                  // 取得 java 的堆栈
                  if (javaThread != null) {
                        StackTraceElement elements[] = javaThread.getStackTrace();
                        if (elements != null && elements.length > 0) {
                              StringBuffer javaStack = new StringBuffer();
                              
                              int size = elements.length;
                              for (int i = size - 1; i >= 0; i--) {
                                    StackTraceElement element = elements[i];
                                    if (element.isNativeMethod()) {
                                          javaStack.append(
                                                      String.format(
                                                                  "%1$s.%2$s (Native Method)\n", 
                                                                  element.getClassName(), 
                                                                  element.getMethodName()));
                                    }
                                    else {
                                          javaStack.append(
                                                      String.format(
                                                                  "%1$s.%2$s(%3$s:%4$d)\n", 
                                                                  element.getClassName(), 
                                                                  element.getMethodName(), 
                                                                  element.getFileName(), 
                                                                  element.getLineNumber()));
                                    }
                              }
                              buffer.append("###################################################################\n");
                              buffer.append("# java crash                                                      #\n");
                              buffer.append("###################################################################\n");
                              buffer.append("java thread: " + threadName + "\n");
                              buffer.append("java breakpad: " + "\n");
                              buffer.append(javaStack.toString());
                        }
                  }
            }
            System.out.println("zd-info" + buffer.toString());
      }
}
