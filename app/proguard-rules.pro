###################################################
## Reglas de Keep para tu IME y vistas personalizadas
###################################################
-keep public class * extends android.inputmethodservice.InputMethodService {
    public <init>(...);
}
-keep class com.bwt.securechats.inputmethod.R { *; }
-keep class com.bwt.securechats.inputmethod.R$* { *; }
-keep class com.bwt.securechats.inputmethod.BuildConfig { *; }

###################################################
## Jackson (optimizado)
###################################################
-keep class com.fasterxml.jackson.** { *; }
-keep @com.fasterxml.jackson.annotation.JsonIgnoreProperties class * { *; }
-keep @com.fasterxml.jackson.annotation.JsonCreator class * { *; }
-keep @com.fasterxml.jackson.annotation.JsonProperty class * { *; }
-dontwarn com.fasterxml.jackson.**

###################################################
## libsignal-android (optimizado)
###################################################
-keep class org.signal.libsignal.** { *; }
-dontwarn org.signal.libsignal.**
-dontwarn org.whispersystems.**
-keep class org.whispersystems.** { *; }

###################################################
## Protobuf (javalite) - optimizado
###################################################
-keep class com.google.protobuf.GeneratedMessageLite { *; }
-keep class com.google.protobuf.GeneratedMessageLite$Builder { *; }
-keepclassmembers class * extends com.google.protobuf.GeneratedMessageLite {
    public static com.google.protobuf.Parser parser();
}
-keep class com.google.protobuf.MessageLite { *; }
-keep class com.google.protobuf.ExtensionLite { *; }
-dontwarn com.google.protobuf.**

###################################################
## Bouncy Castle (optimizado)
###################################################
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }

###################################################
## Android Security Crypto
###################################################
-keep class androidx.security.crypto.** { *; }
-dontwarn androidx.security.crypto.**

###################################################
## Atributos y anotaciones
###################################################
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes EnclosingMethod
-keepattributes InnerClasses

###################################################
## Optimizaciones para reducir tamaño
###################################################
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose
-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*
-optimizationpasses 5
-allowaccessmodification

###################################################
## Eliminación de código de debug/testing
###################################################
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int d(...);
    public static int e(...);
}

###################################################
## Eliminación de checks innecesarios
###################################################
-assumenosideeffects class java.lang.System {
    public static void gc();
    public static long currentTimeMillis();
    public static void arraycopy(java.lang.Object, int, java.lang.Object, int, int);
}
