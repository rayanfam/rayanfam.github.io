---
title: "Get everything from .Net Reflection"
date: "2017-10-31"
categories: 
  - "net-framework"
  - "programming"
tags: 
  - "net-reflection"
  - "c-plugin"
  - "c-reflection"
  - "create-plugin"
  - "dll-plugin"
  - "dynamically-call-function"
  - "invoke-function"
coverImage: "../../assets/images/colorful-pencils.jpg"
comments: true
author:
  name: Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/colorful-pencils.jpg)

In the previous posts, I’d explained about low-level languages and play around kernel-mode reversing but now let’s dig into the high-level languages. In this post, I’m gonna share a comprehensive method that took more than two weeks for me to build such small and perfect function to play with .Net framework reflection. I also share this functions in my GitHub which can be accessed through [this link](https://github.com/SinaKarvandi/UseAllOfDotNetReflection).

.Net reflection gives .net framework a high flexibility by dynamically invoking functions from .net IL files and it has good features which can be used in order to build a plugin-based application in both desktop applications and web applications.

But for now, let me show you what these functions are and how we can use them.

I create two methods to cover all the possibilities in which a target function can be defined, the first one is for situations where you have a function that doesn't need any argument.

It implemented as below :

```
        static object InvokeAssemblyWithoutArgumant(string Path, string MethodName, object[] ArgumantsToContructor = null)
        {
            object ret = null;
            System.Reflection.Assembly myDllAssembly =
            System.Reflection.Assembly.LoadFile(Path);
            if (ArgumantsToContructor == null)
            {
                foreach (Type item in myDllAssembly.GetTypes())
                {
                    ret = item.GetMethod(MethodName).Invoke(Activator.CreateInstance(item), null);
                }
            }
            else
            {
                foreach (Type item in myDllAssembly.GetTypes())
                {
                    ret = item.GetMethod(MethodName).Invoke(Activator.CreateInstance(item, ArgumantsToContructor), null);
                }
            }
            return ret;
        }
```

and the second one :

```
       static object InvokeAssemblyWithArgumant(string Path, string MethodName, object[] argumantToMethod, object[] ArgumantsToContructor = null)
        {
            object ret = null;
            System.Reflection.Assembly myDllAssembly =
            System.Reflection.Assembly.LoadFile(Path);
            if (ArgumantsToContructor == null)
            {
                foreach (Type item in myDllAssembly.GetTypes())
                {
                    ret = item.GetMethod(MethodName).Invoke(Activator.CreateInstance(item), argumantToMethod);
                }
            }
            else
            {
                foreach (Type item in myDllAssembly.GetTypes())
                {
                     ret = item.GetMethod(MethodName).Invoke(Activator.CreateInstance(item, ArgumantsToContructor), argumantToMethod);
                }
            }
            return ret;
        }
```

The second one is used for situations where you wanna pass the parameter(s) to the function.

For instance ...

Consider you built a class library (.dll plugin) from the Visual Studio with the following syntax :

```
    public class Class1
    {
        public Class1(string Arg1)
        {
            //Make program ready for first usage
            System.Windows.Forms.MessageBox.Show("Constructor Invoked !" + Arg1);

        }
        public static string MyPluginFunction1(int a, int b)
        {
            System.Windows.Forms.MessageBox.Show("I'm here in MyPluginFunction.(Args:" + a + "-" + b + ")");
            // Do what to want to do as a plugin
            return "Successful";
        }

        public static string MyPluginFunction2()
        {
            System.Windows.Forms.MessageBox.Show("I'm here in MyPluginFunction (without arg).");
            // Do what to want to do as a plugin
            return "Successful";
        }
    }
```

If you want to call **MyPluginFunction1** then you should use the second method which gives an array of object to pass to the method.

```
            //dll path (Plugin Path)
            string PathToPlugin = Environment.CurrentDirectory + "\\Plugin.dll"; // it's extension can be anything !
            // you can also load assembly from a base64 string.
            InvokeAssemblyWithArgumant(PathToPlugin, "MyPluginFunction1", new object[] { 1, 2 }, new object[] { "Sample Arg to constructor" });
```

If you want to call **MyPluginFunction2** then you should use the first method which invokes the method directly without any arguments.

```
            //dll path (Plugin Path)
            string PathToPlugin = Environment.CurrentDirectory + "\\Plugin.dll"; // it's extension can be anything !
            // you can also load assembly from a base64 string.
            InvokeAssemblyWithoutArgumant(PathToPlugin, "MyPluginFunction2", new object[] { "Sample Arg to constructor" });
```

**Important Note**: If you have an exception like, **object reference not set to an instance** it is because the method name is incorrect or you invoke a **non-static** function within a **static** function or invoke a **static** function within a **non-static** function so please keep in mind the invoker function and target function should have the same state.

 

This post is also available on Github :

[https://github.com/SinaKarvandi/UseAllOfDotNetReflection](https://github.com/SinaKarvandi/UseAllOfDotNetReflection)
