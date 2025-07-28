#import "../YTLitePlus.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

// Security constants
#define SECURITY_KEY_AUTH_STATE @"ytlp_security_authenticated"
#define SECURITY_KEY_SEQUENCE_STATE @"ytlp_security_sequence_state"
#define BUTTON_HOLD_DURATION 5.0
#define KEYCHAIN_SERVICE @"com.ytliteplus.security"
#define KEYCHAIN_ACCOUNT @"auth_state"

// Security enums
typedef NS_ENUM(NSInteger, SecuritySequenceState) {
    SecuritySequenceStateInitial = 0,
    SecuritySequenceStateFirstButtonPressed = 1,
    SecuritySequenceStateSecondButtonPressed = 2,
    SecuritySequenceStateAuthenticated = 3
};

@interface SecurityLayerManager : NSObject
@property (nonatomic, assign) SecuritySequenceState sequenceState;
@property (nonatomic, strong) NSTimer *resetTimer;
@property (nonatomic, strong) NSTimer *holdTimer;
@property (nonatomic, assign) BOOL isAuthenticated;
+ (instancetype)sharedManager;
- (BOOL)isAuthenticatedSecurely;
- (void)setAuthenticationState:(BOOL)authenticated;
- (void)handleButtonPress:(NSInteger)buttonIndex;
- (void)resetSequence;
- (void)showStopwatchInterface;
- (void)showActualApp;
@end

@interface StopwatchViewController : UIViewController
@property (nonatomic, strong) UILabel *timeLabel;
@property (nonatomic, strong) UIButton *startStopButton;
@property (nonatomic, strong) UIButton *resetButton;
@property (nonatomic, strong) UIButton *lapButton;
@property (nonatomic, strong) NSTimer *stopwatchTimer;
@property (nonatomic, assign) NSTimeInterval elapsedTime;
@property (nonatomic, assign) BOOL isRunning;
@property (nonatomic, strong) SecurityLayerManager *securityManager;
@end

@implementation SecurityLayerManager

+ (instancetype)sharedManager {
    static SecurityLayerManager *sharedManager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedManager = [[self alloc] init];
    });
    return sharedManager;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        self.sequenceState = SecuritySequenceStateInitial;
        self.isAuthenticated = [self isAuthenticatedSecurely];
    }
    return self;
}

// Securely store authentication state in keychain
- (BOOL)isAuthenticatedSecurely {
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge NSString *)kSecClass] = (__bridge NSString *)kSecClassGenericPassword;
    query[(__bridge NSString *)kSecAttrService] = KEYCHAIN_SERVICE;
    query[(__bridge NSString *)kSecAttrAccount] = KEYCHAIN_ACCOUNT;
    query[(__bridge NSString *)kSecReturnData] = @YES;
    query[(__bridge NSString *)kSecMatchLimit] = (__bridge NSString *)kSecMatchLimitOne;
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status == errSecSuccess && result != NULL) {
        NSData *data = (__bridge_transfer NSData *)result;
        NSString *authState = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        return [authState isEqualToString:@"authenticated"];
    }
    
    return NO;
}

- (void)setAuthenticationState:(BOOL)authenticated {
    self.isAuthenticated = authenticated;
    
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge NSString *)kSecClass] = (__bridge NSString *)kSecClassGenericPassword;
    query[(__bridge NSString *)kSecAttrService] = KEYCHAIN_SERVICE;
    query[(__bridge NSString *)kSecAttrAccount] = KEYCHAIN_ACCOUNT;
    
    if (authenticated) {
        NSString *authState = @"authenticated";
        NSData *authData = [authState dataUsingEncoding:NSUTF8StringEncoding];
        
        // Try to update existing item first
        NSMutableDictionary *updateAttributes = [NSMutableDictionary dictionary];
        updateAttributes[(__bridge NSString *)kSecValueData] = authData;
        
        OSStatus updateStatus = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)updateAttributes);
        
        if (updateStatus == errSecItemNotFound) {
            // Item doesn't exist, add it
            query[(__bridge NSString *)kSecValueData] = authData;
            query[(__bridge NSString *)kSecAttrAccessible] = (__bridge NSString *)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
            SecItemAdd((__bridge CFDictionaryRef)query, NULL);
        }
    } else {
        // Remove authentication
        SecItemDelete((__bridge CFDictionaryRef)query);
    }
}

- (void)handleButtonPress:(NSInteger)buttonIndex {
    // Reset any existing timers
    [self.holdTimer invalidate];
    [self.resetTimer invalidate];
    
    // Start hold timer for button press
    self.holdTimer = [NSTimer scheduledTimerWithTimeInterval:BUTTON_HOLD_DURATION
                                                      target:self
                                                    selector:@selector(buttonHoldCompleted:)
                                                    userInfo:@{@"buttonIndex": @(buttonIndex)}
                                                     repeats:NO];
    
    // Set reset timer to reset sequence if no action for 10 seconds
    self.resetTimer = [NSTimer scheduledTimerWithTimeInterval:10.0
                                                       target:self
                                                     selector:@selector(resetSequence)
                                                     userInfo:nil
                                                      repeats:NO];
}

- (void)buttonHoldCompleted:(NSTimer *)timer {
    NSInteger buttonIndex = [timer.userInfo[@"buttonIndex"] integerValue];
    
    switch (self.sequenceState) {
        case SecuritySequenceStateInitial:
            if (buttonIndex == 0) { // Start/Stop button
                self.sequenceState = SecuritySequenceStateFirstButtonPressed;
                NSLog(@"[YTLitePlus Security] First button sequence completed");
            } else {
                [self resetSequence];
            }
            break;
            
        case SecuritySequenceStateFirstButtonPressed:
            if (buttonIndex == 1) { // Reset button
                self.sequenceState = SecuritySequenceStateAuthenticated;
                [self setAuthenticationState:YES];
                [self showActualApp];
                NSLog(@"[YTLitePlus Security] Authentication sequence completed - access granted");
            } else {
                [self resetSequence];
            }
            break;
            
        default:
            [self resetSequence];
            break;
    }
}

- (void)resetSequence {
    [self.holdTimer invalidate];
    [self.resetTimer invalidate];
    self.sequenceState = SecuritySequenceStateInitial;
    NSLog(@"[YTLitePlus Security] Sequence reset");
}

- (void)showStopwatchInterface {
    // This will be called to show the dummy stopwatch
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if (!keyWindow) {
        keyWindow = [UIApplication sharedApplication].windows.firstObject;
    }
    
    StopwatchViewController *stopwatchVC = [[StopwatchViewController alloc] init];
    stopwatchVC.securityManager = self;
    
    UIViewController *rootVC = keyWindow.rootViewController;
    if ([rootVC isKindOfClass:[UINavigationController class]]) {
        [(UINavigationController *)rootVC pushViewController:stopwatchVC animated:YES];
    } else {
        UINavigationController *navController = [[UINavigationController alloc] initWithRootViewController:stopwatchVC];
        [rootVC presentViewController:navController animated:YES completion:nil];
    }
}

- (void)showActualApp {
    // Dismiss the stopwatch and show actual settings
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if (!keyWindow) {
        keyWindow = [UIApplication sharedApplication].windows.firstObject;
    }
    
    UIViewController *rootVC = keyWindow.rootViewController;
    if (rootVC.presentedViewController) {
        [rootVC.presentedViewController dismissViewControllerAnimated:YES completion:nil];
    }
}

@end

@implementation StopwatchViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.title = @"Stopwatch";
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.elapsedTime = 0.0;
    self.isRunning = NO;
    
    [self setupUI];
}

- (void)setupUI {
    // Time display
    self.timeLabel = [[UILabel alloc] init];
    self.timeLabel.text = @"00:00.00";
    self.timeLabel.font = [UIFont monospacedDigitSystemFontOfSize:48.0 weight:UIFontWeightThin];
    self.timeLabel.textAlignment = NSTextAlignmentCenter;
    self.timeLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.timeLabel];
    
    // Buttons container
    UIStackView *buttonStack = [[UIStackView alloc] init];
    buttonStack.axis = UILayoutConstraintAxisHorizontal;
    buttonStack.distribution = UIStackViewDistributionFillEqually;
    buttonStack.spacing = 20;
    buttonStack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:buttonStack];
    
    // Start/Stop button (Index 0 - First button in sequence)
    self.startStopButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.startStopButton.backgroundColor = [UIColor systemGreenColor];
    self.startStopButton.layer.cornerRadius = 50;
    [self.startStopButton setTitle:@"Start" forState:UIControlStateNormal];
    [self.startStopButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.startStopButton.titleLabel.font = [UIFont systemFontOfSize:18 weight:UIFontWeightMedium];
    [self.startStopButton addTarget:self action:@selector(startStopButtonPressed:) forControlEvents:UIControlEventTouchDown];
    [self.startStopButton addTarget:self action:@selector(startStopButtonReleased:) forControlEvents:UIControlEventTouchUpInside | UIControlEventTouchUpOutside];
    
    // Reset button (Index 1 - Second button in sequence)
    self.resetButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.resetButton.backgroundColor = [UIColor systemGrayColor];
    self.resetButton.layer.cornerRadius = 50;
    [self.resetButton setTitle:@"Reset" forState:UIControlStateNormal];
    [self.resetButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.resetButton.titleLabel.font = [UIFont systemFontOfSize:18 weight:UIFontWeightMedium];
    [self.resetButton addTarget:self action:@selector(resetButtonPressed:) forControlEvents:UIControlEventTouchDown];
    [self.resetButton addTarget:self action:@selector(resetButtonReleased:) forControlEvents:UIControlEventTouchUpInside | UIControlEventTouchUpOutside];
    
    // Lap button (Decoy button)
    self.lapButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.lapButton.backgroundColor = [UIColor systemOrangeColor];
    self.lapButton.layer.cornerRadius = 50;
    [self.lapButton setTitle:@"Lap" forState:UIControlStateNormal];
    [self.lapButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.lapButton.titleLabel.font = [UIFont systemFontOfSize:18 weight:UIFontWeightMedium];
    [self.lapButton addTarget:self action:@selector(lapButtonPressed) forControlEvents:UIControlEventTouchUpInside];
    
    [buttonStack addArrangedSubview:self.resetButton];
    [buttonStack addArrangedSubview:self.startStopButton];
    [buttonStack addArrangedSubview:self.lapButton];
    
    // Constraints
    [NSLayoutConstraint activateConstraints:@[
        [self.timeLabel.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.timeLabel.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:-100],
        
        [buttonStack.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [buttonStack.topAnchor constraintEqualToAnchor:self.timeLabel.bottomAnchor constant:100],
        [buttonStack.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:40],
        [buttonStack.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-40],
        
        [self.startStopButton.heightAnchor constraintEqualToConstant:100],
        [self.resetButton.heightAnchor constraintEqualToConstant:100],
        [self.lapButton.heightAnchor constraintEqualToConstant:100]
    ]];
}

- (void)startStopButtonPressed:(UIButton *)sender {
    // Handle security sequence
    [self.securityManager handleButtonPress:0];
    
    // Normal stopwatch functionality
    if (!self.isRunning) {
        [self startStopwatch];
    } else {
        [self stopStopwatch];
    }
}

- (void)startStopButtonReleased:(UIButton *)sender {
    // Could add additional logic here if needed
}

- (void)resetButtonPressed:(UIButton *)sender {
    // Handle security sequence
    [self.securityManager handleButtonPress:1];
}

- (void)resetButtonReleased:(UIButton *)sender {
    // Normal reset functionality
    [self resetStopwatch];
}

- (void)lapButtonPressed {
    // Decoy button - just shows a fake lap time
    if (self.isRunning) {
        NSLog(@"[Stopwatch] Lap time: %.2f", self.elapsedTime);
    }
}

- (void)startStopwatch {
    self.isRunning = YES;
    [self.startStopButton setTitle:@"Stop" forState:UIControlStateNormal];
    self.startStopButton.backgroundColor = [UIColor systemRedColor];
    
    self.stopwatchTimer = [NSTimer scheduledTimerWithTimeInterval:0.01
                                                           target:self
                                                         selector:@selector(updateTimer)
                                                         userInfo:nil
                                                          repeats:YES];
}

- (void)stopStopwatch {
    self.isRunning = NO;
    [self.startStopButton setTitle:@"Start" forState:UIControlStateNormal];
    self.startStopButton.backgroundColor = [UIColor systemGreenColor];
    
    [self.stopwatchTimer invalidate];
    self.stopwatchTimer = nil;
}

- (void)resetStopwatch {
    [self stopStopwatch];
    self.elapsedTime = 0.0;
    [self updateTimeDisplay];
}

- (void)updateTimer {
    self.elapsedTime += 0.01;
    [self updateTimeDisplay];
}

- (void)updateTimeDisplay {
    int minutes = (int)(self.elapsedTime / 60);
    int seconds = (int)self.elapsedTime % 60;
    int centiseconds = (int)((self.elapsedTime - (int)self.elapsedTime) * 100);
    
    self.timeLabel.text = [NSString stringWithFormat:@"%02d:%02d.%02d", minutes, seconds, centiseconds];
}

- (void)dealloc {
    [self.stopwatchTimer invalidate];
    [self.securityManager resetSequence];
}

@end

// Hook into settings to show security layer when not authenticated
%hook YTSettingsSectionItemManager
- (void)updateYTLitePlusSectionWithEntry:(id)entry {
    // Only show security layer if it's enabled
    if (!IS_ENABLED(@"securityLayer_enabled")) {
        %orig;
        return;
    }
    
    SecurityLayerManager *securityManager = [SecurityLayerManager sharedManager];
    
    if (![securityManager isAuthenticatedSecurely]) {
        // Show stopwatch interface instead of settings
        dispatch_async(dispatch_get_main_queue(), ^{
            [securityManager showStopwatchInterface];
        });
        return;
    }
    
    // User is authenticated, show normal settings
    %orig;
}
%end

// Reset authentication on app termination for additional security
%hook YTAppDelegate
- (void)applicationWillTerminate:(UIApplication *)application {
    %orig;
    
    // Only reset if security layer is enabled
    if (IS_ENABLED(@"securityLayer_enabled")) {
        // Optional: Reset authentication on app termination
        // Comment out the next two lines if you want authentication to persist across app restarts
        SecurityLayerManager *securityManager = [SecurityLayerManager sharedManager];
        [securityManager setAuthenticationState:NO];
    }
}
%end