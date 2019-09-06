/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.github.omadahealth.lollipin.lib.managers;

import android.annotation.TargetApi;
import android.os.Build;
import android.os.Handler;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

import com.github.omadahealth.lollipin.lib.R;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

@TargetApi(Build.VERSION_CODES.M)
public class BiometricHelper extends BiometricPrompt.AuthenticationCallback {

    /**
     * Alias for our key in the Android Key Store
     **/
    private static final String KEY_NAME = "my_key";

    /**
     * The {@link Cipher} used to init {@link BiometricPrompt}
     */
    private Cipher mCipher;
    /**
     * The {@link KeyStore} used to initialize the key {@link #KEY_NAME}
     */
    private KeyStore mKeyStore;
    /**
     * The {@link BiometricHelper.Callback} used to return success or error.
     */
    private final Callback mCallback;

    /**
     * The {@link Executor} used for the {@link BiometricPrompt}
     */
    private Executor mExecutor;

    /**
     * The {@link BiometricPrompt} object used for authentication
     */
    private BiometricPrompt mBiometricPrompt;

    /**
     * The {@link BiometricPrompt.PromptInfo} used in the authenticate method of
     * {@link BiometricPrompt}
     */
    private BiometricPrompt.PromptInfo mBiometricInfo;

    /**
     * Handler used for handling UI events
     */
    private Handler mHandler;

    /**
     * Constructor for {@link BiometricHelper}.
     */

    BiometricHelper(FragmentActivity activity, Callback callback) {
        mCallback = callback;
        mExecutor = Executors.newSingleThreadExecutor();
        mBiometricPrompt = new BiometricPrompt(activity, mExecutor, this);
        mBiometricInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(activity.getString(R.string.biometric_prompt_title))
                .setNegativeButtonText(activity.getString(R.string.biometric_use_pin_code))
                .build();
        mHandler = new Handler(activity.getMainLooper());
    }

    void start() throws SecurityException {
        if (initCipher()) {
            final BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(mCipher);
            mHandler.post(new Runnable() {
                @Override
                public void run() {
                    mBiometricPrompt.authenticate(mBiometricInfo, cryptoObject);
                }
            });
        }
    }

    void stop() {
        mBiometricPrompt.cancelAuthentication();
    }

    @Override
    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                mCallback.onAuthenticated();
            }
        });
    }


    @Override
    public void onAuthenticationError(final int errMsgId, @NonNull final CharSequence errString) {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                handleError(errMsgId);
                mCallback.onError(errMsgId == BiometricPrompt.ERROR_NEGATIVE_BUTTON || errMsgId == BiometricPrompt.ERROR_USER_CANCELED, errString.toString());
            }
        });
    }

    private void handleError(int errMsgId) {
        if (errMsgId == BiometricPrompt.ERROR_HW_NOT_PRESENT ||
                errMsgId == BiometricPrompt.ERROR_HW_UNAVAILABLE ||
                errMsgId == BiometricPrompt.ERROR_NO_BIOMETRICS ||
                errMsgId == BiometricPrompt.ERROR_LOCKOUT_PERMANENT ||
                errMsgId == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                errMsgId == BiometricPrompt.ERROR_USER_CANCELED) {
            mBiometricPrompt.cancelAuthentication();
        }
    }

    @Override
    public void onAuthenticationFailed() {}

    /**
     * Initialize the {@link Cipher} instance with the created key in the {@link #createKey()}
     * method.
     *
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */
    private boolean initCipher() {
        try {
            if (mKeyStore == null) {
                mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            }
            createKey();
            mKeyStore.load(null);
            SecretKey key = (SecretKey) mKeyStore.getKey(KEY_NAME, null);
            mCipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            mCipher.init(Cipher.ENCRYPT_MODE, key);
            return true;
        } catch (NoSuchPaddingException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            return false;
        }
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     */
    private void createKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * The interface used to call the original Activity/Fragment... that uses this helper.
     */
    public interface Callback {
        void onAuthenticated();
        void onError(boolean selfCancel, String errorString);
    }
}