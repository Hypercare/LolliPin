package com.github.omadahealth.lollipin.lib.managers;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.biometric.BiometricManager;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.github.omadahealth.lollipin.lib.PinCompatActivity;
import com.github.omadahealth.lollipin.lib.R;
import com.github.omadahealth.lollipin.lib.enums.KeyboardButtonEnum;
import com.github.omadahealth.lollipin.lib.interfaces.KeyboardButtonClickedListener;
import com.github.omadahealth.lollipin.lib.views.KeyboardView;
import com.github.omadahealth.lollipin.lib.views.PinCodeRoundView;

import java.util.Arrays;
import java.util.List;

import static androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS;

/**
 * Created by stoyan and olivier on 1/13/15.
 * The activity that appears when the password needs to be set or has to be asked.
 * Call this activity in normal or singleTop mode (not singleTask or singleInstance, it does not work
 * with {@link android.app.Activity#startActivityForResult(android.content.Intent, int)}).
 */
public abstract class AppLockActivity extends PinCompatActivity implements
        KeyboardButtonClickedListener,
        View.OnClickListener,
        BiometricHelper.Callback {

    public static final String TAG = AppLockActivity.class.getSimpleName();
    public static final String ACTION_CANCEL = TAG + ".actionCancelled";
    private static final int DEFAULT_PIN_LENGTH = 4;

    protected TextView mStepTextView;
    protected TextView mForgotTextView;
    protected PinCodeRoundView mPinCodeRoundView;
    protected KeyboardView mKeyboardView;

    protected LockManager mLockManager;
    protected BiometricHelper mBiometricHelper;

    protected int mType = AppLock.UNLOCK_PIN;
    protected int mAttempts = 1;

    protected String mPinCode;
    protected String mOldPinCode;
    private boolean isCodeSuccessful = false;

    /**
     * First creation
     */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(getContentView());
        initLayout(getIntent());
        initBiometrics();
    }

    /**
     * If called in singleTop mode
     */
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        initLayout(intent);
    }

    /**
     * Init completely the layout, depending of the extra {@link com.github.omadahealth.lollipin.lib.managers.AppLock#EXTRA_TYPE}
     */
    private void initLayout(Intent intent) {
        overridePendingTransition(R.anim.nothing, R.anim.nothing);

        Bundle extras = intent.getExtras();
        if (extras != null) mType = extras.getInt(AppLock.EXTRA_TYPE, AppLock.UNLOCK_PIN);

        mLockManager = LockManager.getInstance();
        mPinCode = "";
        mOldPinCode = "";

        enableAppLockerIfDoesNotExist();
        mLockManager.getAppLock().setPinChallengeCancelled(false);

        mStepTextView = findViewById(R.id.pin_code_step_textview);
        mPinCodeRoundView = findViewById(R.id.pin_code_round_view);
        mPinCodeRoundView.setPinLength(getPinLength());
        mForgotTextView = findViewById(R.id.pin_code_forgot_textview);
        mForgotTextView.setOnClickListener(this);
        mKeyboardView = findViewById(R.id.pin_code_keyboard_view);
        mKeyboardView.setKeyboardButtonClickedListener(this);
        mKeyboardView.showBiometricsButton(mType);

        int logoId = mLockManager.getAppLock().getLogoId();
        ImageView logoImage = findViewById(R.id.pin_code_logo_imageview);
        if (logoId != AppLock.LOGO_ID_NONE) {
            logoImage.setVisibility(View.VISIBLE);
            logoImage.setImageResource(logoId);
        }
        mForgotTextView.setText(getForgotText());
        setForgotTextVisibility();

        setStepText();
    }

    private void initBiometrics() {
        boolean canAuthenticate = BiometricManager.from(this).canAuthenticate() == BIOMETRIC_SUCCESS;
        boolean fingerprintEnabled = mLockManager.getAppLock().isFingerprintAuthEnabled();
        if (mType == AppLock.UNLOCK_PIN && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && canAuthenticate && fingerprintEnabled) {
            mBiometricHelper = new BiometricHelper(this);
            if (mLockManager.getAppLock().isFingerprintAuthEnabled()) {
                mBiometricHelper.start(this);
            }
        }
    }

    /**
     * Re enable {@link AppLock} if it has been collected to avoid
     * {@link NullPointerException}.
     */
    @SuppressWarnings("unchecked")
    private void enableAppLockerIfDoesNotExist() {
        try {
            if (mLockManager.getAppLock() == null) {
                mLockManager.enableAppLock(this, getCustomAppLockActivityClass());
            }
        } catch (Exception e) {
            Log.e(TAG, e.toString());
        }
    }

    /**
     * Init the {@link #mStepTextView} based on {@link #mType}
     */
    private void setStepText() {
        mStepTextView.setText(getStepText(mType));
    }

    /**
     * Gets the {@link String} to be used in the {@link #mStepTextView} based on {@link #mType}
     *
     * @param reason The {@link #mType} to return a {@link String} for
     * @return The {@link String} for the {@link AppLockActivity}
     */
    public String getStepText(int reason) {
        String msg = null;
        switch (reason) {
            case AppLock.DISABLE_PINLOCK:
                msg = getString(R.string.pin_code_step_disable, this.getPinLength());
                break;
            case AppLock.ENABLE_PINLOCK:
                msg = getString(R.string.pin_code_step_create, this.getPinLength());
                break;
            case AppLock.CHANGE_PIN:
                msg = getString(R.string.pin_code_step_change, this.getPinLength());
                break;
            case AppLock.UNLOCK_PIN:
                msg = getString(R.string.pin_code_step_unlock, this.getPinLength());
                break;
            case AppLock.CONFIRM_PIN:
                msg = getString(R.string.pin_code_step_enable_confirm, this.getPinLength());
                break;
        }
        return msg;
    }

    public String getForgotText() {
        return getString(R.string.pin_code_forgot_text);
    }

    private void setForgotTextVisibility(){
        mForgotTextView.setVisibility(mLockManager.getAppLock().shouldShowForgot(mType) ? View.VISIBLE : View.GONE);
    }

    /**
     * Overrides to allow a slide_down animation when finishing
     */
    @Override
    public void finish() {
        super.finish();

        //If code successful, reset the timer
        if (isCodeSuccessful) {
            if (mLockManager != null) {
                AppLock appLock = mLockManager.getAppLock();
                if (appLock != null) {
                    appLock.setLastActiveMillis();
                }
            }
        }

        mBiometricHelper = null;
        overridePendingTransition(R.anim.nothing, R.anim.slide_down);
    }

    /**
     * Add the button clicked to {@link #mPinCode} each time.
     * Refreshes also the {@link com.github.omadahealth.lollipin.lib.views.PinCodeRoundView}
     */
    @Override
    public void onKeyboardClick(KeyboardButtonEnum keyboardButtonEnum) {
        int value = keyboardButtonEnum.getButtonValue();
        if (keyboardButtonEnum == KeyboardButtonEnum.BUTTON_BIOMETRICS) {
            if (mBiometricHelper != null) mBiometricHelper.start(AppLockActivity.this);
            return;
        }
        if (mPinCode.length() < this.getPinLength()) {
            if (value == KeyboardButtonEnum.BUTTON_CLEAR.getButtonValue()) {
                if (!mPinCode.isEmpty()) {
                    setPinCode(mPinCode.substring(0, mPinCode.length() - 1));
                } else {
                    setPinCode("");
                }
            } else {
                setPinCode(mPinCode + value);
            }
        }
    }

    /**
     * Called at the end of the animation of the {@link com.andexert.library.RippleView}
     * Calls {@link #onPinCodeInput} when {@link #mPinCode}
     */
    @Override
    public void onRippleAnimationEnd() {
        if (mPinCode.length() == this.getPinLength()) {
            onPinCodeInput();
        }
    }

    /**
     * Switch over the {@link #mType} to determine if the password is ok, if we should pass to the next step etc...
     */
    protected void onPinCodeInput() {
        switch (mType) {
            case AppLock.DISABLE_PINLOCK:
                if (mLockManager.getAppLock().checkPasscode(mPinCode)) {
                    setResult(RESULT_OK);
                    mLockManager.getAppLock().setPasscode(null);
                    onPinCodeSuccess();
                    finish();
                } else {
                    onPinCodeError();
                }
                break;
            case AppLock.ENABLE_PINLOCK:
                mOldPinCode = mPinCode;
                setPinCode("");
                mType = AppLock.CONFIRM_PIN;
                setStepText();
                setForgotTextVisibility();
                break;
            case AppLock.CONFIRM_PIN:
                if (mPinCode.equals(mOldPinCode)) {
                    setResult(RESULT_OK);
                    mLockManager.getAppLock().setPasscode(mPinCode);
                    onPinCodeSuccess();
                    finish();
                } else {
                    mOldPinCode = "";
                    setPinCode("");
                    mType = AppLock.ENABLE_PINLOCK;
                    setStepText();
                    setForgotTextVisibility();
                    onPinCodeError();
                }
                break;
            case AppLock.CHANGE_PIN:
                if (mLockManager.getAppLock().checkPasscode(mPinCode)) {
                    mType = AppLock.ENABLE_PINLOCK;
                    setStepText();
                    setForgotTextVisibility();
                    setPinCode("");
                    onPinCodeSuccess();
                } else {
                    onPinCodeError();
                }
                break;
            case AppLock.UNLOCK_PIN:
                if (mLockManager.getAppLock().checkPasscode(mPinCode)) {
                    onAuthenticated();
                } else {
                    onPinCodeError();
                }
                break;
            default:
                break;
        }
    }

    /**
     * Override {@link #onBackPressed()} to prevent user for finishing the activity
     */
    @Override
    public void onBackPressed() {
        if (getBackableTypes().contains(mType)) {
            if (AppLock.UNLOCK_PIN == getType()) {
                mLockManager.getAppLock().setPinChallengeCancelled(true);
                LocalBroadcastManager
                        .getInstance(this)
                        .sendBroadcast(new Intent().setAction(ACTION_CANCEL));
            }
            super.onBackPressed();
        }
    }

    @Override
    public void onAuthenticated() {
        setResult(RESULT_OK);
        onPinCodeSuccess();
        finish();
    }

    @Override
    public void onError(boolean selfCancel, String errorString) {
        if (selfCancel) return;
    }

    /**
     * Gets the list of {@link AppLock} types that are acceptable to be backed out of using
     * the device's back button
     *
     * @return an {@link List<Integer>} of {@link AppLock} types which are backable
     */
    public List<Integer> getBackableTypes() {
        return Arrays.asList(AppLock.CHANGE_PIN, AppLock.DISABLE_PINLOCK);
    }

    /**
     * Displays the information dialog when the user clicks the
     * {@link #mForgotTextView}
     */
    public abstract void showForgotDialog();

    /**
     * Run a shake animation when the password is not valid.
     */
    protected void onPinCodeError() {
        onPinFailure(mAttempts++);
        Thread thread = new Thread() {
            public void run() {
                mPinCode = "";
                mPinCodeRoundView.refresh(mPinCode.length());
                Animation animation = AnimationUtils.loadAnimation(
                        AppLockActivity.this, R.anim.shake);
                mKeyboardView.startAnimation(animation);
            }
        };
        runOnUiThread(thread);
    }

    protected void onPinCodeSuccess() {
        isCodeSuccessful = true;
        onPinSuccess(mAttempts);
        mAttempts = 1;
    }

    /**
     * Set the pincode and refreshes the {@link com.github.omadahealth.lollipin.lib.views.PinCodeRoundView}
     */
    public void setPinCode(String pinCode) {
        mPinCode = pinCode;
        mPinCodeRoundView.refresh(mPinCode.length());
    }


    /**
     * Returns the type of this {@link com.github.omadahealth.lollipin.lib.managers.AppLockActivity}
     */
    public int getType() {
        return mType;
    }

    /**
     * When we click on the {@link #mForgotTextView} handle the pop-up
     * dialog
     *
     * @param view {@link #mForgotTextView}
     */
    @Override
    public void onClick(View view) {
        showForgotDialog();
    }

    /**
     * When the user has failed a pin challenge
     *
     * @param attempts the number of attempts the user has used
     */
    public abstract void onPinFailure(int attempts);

    /**
     * When the user has succeeded at a pin challenge
     *
     * @param attempts the number of attempts the user had used
     */
    public abstract void onPinSuccess(int attempts);

    /**
     * Gets the resource id to the {@link View} to be set with {@link #setContentView(int)}.
     * The custom layout must include the following:
     * - {@link TextView} with an id of pin_code_step_textview
     * - {@link TextView} with an id of pin_code_forgot_textview
     * - {@link PinCodeRoundView} with an id of pin_code_round_view
     * - {@link KeyboardView} with an id of pin_code_keyboard_view
     *
     * @return the resource id to the {@link View}
     */
    public int getContentView() {
        return R.layout.activity_pin_code;
    }

    /**
     * Gets the number of digits in the pin code.  Subclasses can override this to change the
     * length of the pin.
     *
     * @return the number of digits in the PIN
     */
    public int getPinLength() {
        return AppLockActivity.DEFAULT_PIN_LENGTH;
    }

    /**
     * Get the current class extending {@link AppLockActivity} to re-enable {@link AppLock}
     * in case it has been collected
     *
     * @return the current class extending {@link AppLockActivity}
     */
    public Class<? extends AppLockActivity> getCustomAppLockActivityClass() {
        return this.getClass();
    }
}