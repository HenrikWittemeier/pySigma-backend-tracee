from sigma.conversion.state import ConversionState
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule

from sigma.pipelines.tracee import tracee_pipeline
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import (
    ConditionItem,
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
)
from sigma.conversion.deferred import (
    DeferredQueryExpression,
    DeferredTextQueryExpression,
)
import sigma
import re
from typing import ClassVar, Dict, Tuple, Pattern, Optional, Union


class TraceeBackend(TextQueryBackend):
    """Tracee backend."""

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name: ClassVar[str] = "Tracee backend"
    formats: Dict[str, str] = {
        "default": "Tracee GO Signatures",
    }
    requires_pipeline: bool = False

    backend_processing_pipeline : ClassVar[ProcessingPipeline] = tracee_pipeline()
    eq_token: ClassVar[str]  = "=="
    or_token : ClassVar[str] = "||"
    and_token : ClassVar[str] = "&&"
    not_token = "!"

    wildcard_multi: ClassVar[str] = ".*"
    wildcard_single: ClassVar[str] = "."
    eq_expression: ClassVar[str] = (
        "regexp.MustCompile(`^{value}$`).MatchString({field})"  # Expression for field = value
    )
    compare_op_expression: ClassVar[Optional[str]] = (
        "{field} {operator} strconv.Atoi(`{value}`)"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )

    #str_quote: ClassVar[str] = '`'
    #str_quote_pattern: ClassVar[Pattern] = re.compile(r"^$|\d*")
    #str_quote_pattern_negation: ClassVar[bool] = True

    re_escape_char: ClassVar[str] = "\\"
    escape_char: ClassVar[str] = "\\"
    add_escaped: ClassVar[str] = '\n\r\t\\|"()'

    group_expression: ClassVar[str] = "({expr})"

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions"""
        try:
            return self.escape_and_quote_field(cond.field) + self.eq_token + str(cond.value)
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals numeric value expressions are not supported by the backend."
            )

    def __init__(
        self,
        processing_pipeline: Optional[
            "sigma.processing.pipeline.ProcessingPipeline"
        ] = None,
        collect_errors: bool = False,
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Union[str, DeferredQueryExpression],
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> Union[str, DeferredQueryExpression]:
        title = rule.title.replace(" ","").replace("(","").replace(")","").replace("-","_").replace(".","DOT").replace("/","or").replace("\\","").replace(":","")
        finalized_query = f"""package main
    
    import (
        "fmt"
        "regexp"
	    "github.com/aquasecurity/tracee/signatures/helpers"
        "github.com/aquasecurity/tracee/types/detect"
        "github.com/aquasecurity/tracee/types/trace"
        "github.com/aquasecurity/tracee/types/protocol"
    )

    type {title} struct {{
        cb               detect.SignatureHandler
        releaseAgentName string
    }}
    
    
    var {title}Metadata = detect.SignatureMetadata{{
        ID:          "{rule.id}",
        Version:     "1",
        Name:        "{rule.title}",
        EventName:   "{title}",
        Description: "{rule.description.replace("\\","\\\\").replace("\"","\\\\\\\"").replace("\n"," ")}",
        //TraceeLogSource: "{rule.logsource.category}"
        Properties: map[string]interface{{}}{{
            "Severity":             "{rule.level}",
            "Category":             "{rule.tags[0].namespace}",
            "Technique":            "{rule.tags[0].name}",
            "Kubernetes_Technique": "",
            "id":                   "{rule.id}",
            "external_id":          "{rule.id}",
        }},
    }}
    
    func (sig *{title}) Init(ctx detect.SignatureContext) error {{
        sig.cb = ctx.Callback
        return nil
    }}

    func (sig *{title}) GetMetadata() (detect.SignatureMetadata, error) {{
        return {title}Metadata, nil
    }}

    func (sig *{title}) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {{
        return []detect.SignatureEventSelector{{
            {{Source: "{rule.logsource.category}", Name: "{rule.logsource.product}", Origin: "*"}},
        }}, nil
    }}

    func (sig *{title}) OnEvent(event protocol.Event) error {{
        eventObj, ok := event.Payload.(trace.Event)
        if !ok {{
            return fmt.Errorf("invalid event")
        }}
        var file_path, dst, src, dstIP, argv, cmdpath, dstHostname, txtAnswer, httpUserAgent, httpMethod,httpUri,httpHost, httpCookie, httpReferer string
        var dstPort, httpStatusCode int
        var err error
        switch eventObj.EventName {{
        case "file_modification":
            file_path, err = helpers.GetTraceeStringArgumentByName(eventObj, "file_path")
            if err != nil {{
                return err
            }}
        case "net_packet_ipv4":
            dst, err = helpers.GetTraceeStringArgumentByName(eventObj, "dst")
            if err != nil {{
                return err
            }}
            src, err = helpers.GetTraceeStringArgumentByName(eventObj, "src")
            if err != nil {{
                return err
            }}
        case "net_tcp_connect":
            dstIP, err = helpers.GetTraceeStringArgumentByName(eventObj, "dstIP")
            if err != nil {{
                return err
            }}
            dstPort, err = helpers.GetTraceeIntArgumentByName(eventObj, "dstPort")
            if err != nil {{
                return err
            }}
        case "sched_process_exec":
            argv_arr, err  := helpers.GetTraceeSliceStringArgumentByName(eventObj, "argv")
            if err != nil {{
                return err
            }}
            for _, arg := range argv_arr {{
                argv = argv + " " + arg
            }}
            cmdpath, err = helpers.GetTraceeStringArgumentByName(eventObj, "cmdpath")
            if err != nil {{
                return err
            }}
        case "net_packet_dns":
            dns, err := helpers.GetProtoDNSByName(eventObj, "proto_dns")
            if err != nil {{
                return err
            }}
            if len(dns.Questions) > 0{{
                dstHostname = dns.Questions[0].Name
            }}
        case "net_packet_dns_response":
            dns, err := helpers.GetProtoDNSByName(eventObj, "dns_response")
            if err != nil {{
                return err
            }}
            for i:=0;i<len(dns.Answers);i++ {{
                if dns.Answers[i].Type == "TXT"{{
                    for j:=0;j<len(dns.Answers[i].TXTs);j++ {{
                        txtAnswer = txtAnswer + " " + dns.Answers[i].TXTs[j]
                    }}
                }}    
            }}
        case "net_packet_http_request":
            arg, err := helpers.GetTraceeArgumentByName(eventObj, "http_request", helpers.GetArgOps{{DefaultArgs: false}})
            if err != nil {{
                return err
            }}
            
            http, ok := arg.Value.(trace.ProtoHTTPRequest)
            
            if !ok {{
                return nil
            }}  
            httpUserAgent = http.Headers.Get("User-Agent")
            httpReferer = http.Headers.Get("Referer")
            httpMethod = http.Method
            httpUri = http.URIPath
            httpHost = http.Host
            httpCookie = http.Headers.Get("Cookie")
            dstIP, err = helpers.GetTraceeStringArgumentByName(eventObj, "dstIP")
            
        case "net_packet_http_response":
            arg, err := helpers.GetTraceeArgumentByName(eventObj, "http_response", helpers.GetArgOps{{DefaultArgs: false}})
            if err != nil {{
                return err
            }}
            
            http, ok := arg.Value.(trace.ProtoHTTPResponse)
            
            if !ok {{
                return nil
            }}           
            httpStatusCode = http.StatusCode
        }}

            
            
            
            
        if {query} {{
            metadata, err := sig.GetMetadata()
            if err != nil {{
                return err
            }}
            sig.cb(&detect.Finding{{
                SigMetadata: metadata,
                Event:       event,
                Data:        nil,
            }})
        }}
        _ = dstIP
        _ = dstPort
        _ = file_path
        _ = src
        _ = dst
        _ = argv
        _ = cmdpath
        _ = dstHostname
        _ = txtAnswer
        _ = httpUserAgent
        _ = httpMethod
        _ = httpUri
        _ = httpHost
        _ = httpStatusCode
        _ = httpCookie
        _ = httpReferer
        return nil
    }}

    func (sig *{title}) OnSignal(s detect.Signal) error {{
        return nil
    }}
    func (sig *{title}) Close() {{}}
        """
        finalized_query = re.sub(r"(regexp.MustCompile\(`\^[^()]+?[^$])`([^^][^()]+?\).MatchString\()",r"""\g<1>`+"`"+`\g<2>""",finalized_query)
        return finalized_query

