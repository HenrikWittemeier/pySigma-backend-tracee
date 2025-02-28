from dataclasses import dataclass
from itertools import product
from typing import Union, Optional, List
from unicodedata import category

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions import IncludeFieldCondition, MatchStringCondition, LogsourceCondition, \
    RuleProcessingItemAppliedCondition, RuleProcessingCondition, field_name_conditions, \
    RuleContainsDetectionItemCondition, FieldNameProcessingItemAppliedCondition, rule_conditions, \
    detection_item_conditions, FieldNameProcessingCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import ChangeLogsourceTransformation, RuleFailureTransformation, \
    DetectionItemFailureTransformation, FieldMappingTransformation, WildcardPlaceholderTransformation, \
    RegexTransformation, \
    ReplaceStringTransformation, SetValueTransformation, SetFieldTransformation, ValueTransformation, \
    StringValueTransformation, AddFieldnamePrefixTransformation, transformations, Transformation, \
    DropDetectionItemTransformation, AddFieldTransformation, DetectionItemTransformation
from sigma.rule import SigmaRule, SigmaDetectionItem, SigmaDetection

@dataclass
class RuleContainsFieldCondition(RuleProcessingCondition):
    """Returns True if rule contains a detection item that matches the given field name and value."""

    field: Optional[str]

    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        if isinstance(rule, SigmaRule):
            for detection in rule.detection.detections.values():
                if self.find_detection_item(detection):
                    return True
            return False
        elif isinstance(rule, SigmaCorrelationRule):
            return False


    def find_detection_item(self, detection: Union[SigmaDetectionItem, SigmaDetection]) -> bool:
        if isinstance(detection, SigmaDetection):
            for detection_item in detection.detection_items:
                if self.find_detection_item(detection_item):
                    return True
        elif isinstance(detection, SigmaDetectionItem):
            if (
                detection.field is not None
                and detection.field == self.field
            ):
                return True
        else:
            raise TypeError("Parameter of type SigmaDetection or SigmaDetectionItem expected.")

        return False


@dataclass
class RemoveFieldTransformation(Transformation):
    """
    Remove one or multiple fields from the Sigma rules field list. If a given field is not in the
    rules list, it is ignored.
    """

    field: Union[str, List[str]]

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        super().apply(pipeline, rule)
        if isinstance(self.field, str):
            try:
                for idx, item in enumerate(rule.detection.detections['selection'].detection_items):
                    if item.field == self.field:
                        rule.detection.detections['selection'].detection_items.remove(item)
            except ValueError:
                pass
        elif isinstance(self.field, list):
            for field in self.field:
                try:
                    for idx, item in enumerate(rule.detection.detections['selection'].detection_items):
                        if item.field == field:
                            rule.detection.detections['selection'].detection_items.remove(item)
                except ValueError:
                    pass

class AggregateRuleProcessingCondition(RuleProcessingCondition):
    """"""

    def match(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule) -> bool:
        """Match condition on Sigma rule."""
        agg_function_strings = ["| count", "| min", "| max", "| avg", "| sum", "| near"]
        condition_string = " ".join([item.lower() for item in rule.detection.condition])
        if any(f in condition_string for f in agg_function_strings):
            return True
        else:
            return False


def tracee_pipeline():
    return ProcessingPipeline(
        name="Generic Log Sources to Tracee GO Signatures",
        priority=20,
        items=[
            ProcessingItem(
                identifier="tracee_generic_file_event_logsourcemapping",
                transformation=ChangeLogsourceTransformation("tracee",product="file_modification"),
                rule_conditions=[
                    LogsourceCondition(product="linux",category="file_event")
                ]
            ),
            ProcessingItem(
                identifier="tracee_network_connection_tcp_logsourcemapping",
                transformation=ChangeLogsourceTransformation(product="tracee", category="net_tcp_connect"),
                rule_conditions=[
                    LogsourceCondition(product="linux",category="network_connection"),
                    RuleContainsFieldCondition("DestinationIp"),
                    RuleContainsDetectionItemCondition("Initiated",'true')
                ]
            ),
            ProcessingItem(
                identifier="tracee_network_connection_tcp_fieldmapping",
                transformation=FieldMappingTransformation({
                    "DestinationIp": "dstIP",
                    "DestinationPort": "dstPort",
                }),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("tracee_network_connection_tcp_logsourcemapping")
                ],
            ),
            ProcessingItem(
                identifier="tracee_network_connection_tcp_remove_initiated",
                transformation=RemoveFieldTransformation("Initiated"),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("tracee_network_connection_tcp_fieldmapping")
                ]
            ),
            ProcessingItem(
                identifier="tracee_network_connection_ipv4_logsourcemapping",
                transformation=ChangeLogsourceTransformation("tracee", product="net_packet_ipv4"),
                rule_conditions=[
                    LogsourceCondition(product="linux",category="network_connection"),
                    RuleContainsFieldCondition("DestinationIp")
                ]
            ),
            ProcessingItem(
                identifier="tracee_network_connection_dns_logsourcemapping",
                transformation=ChangeLogsourceTransformation("tracee", product="net_packet_dns"),
                rule_conditions=[
                    LogsourceCondition(product="linux", category="network_connection"),
                    RuleContainsFieldCondition("DestinationHostname")
                ]
            ),
            ### TCP
            ProcessingItem(
                identifier="tracee_network_connection_tcp_remove_initiated",
                transformation=RemoveFieldTransformation("Initiated"),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("tracee_network_connection_dns_logsourcemapping")
                ]
            ),
            ### DNS
            ProcessingItem(
                identifier="tracee_dns_request_logsourcemapping",
                transformation=ChangeLogsourceTransformation("tracee", product="net_packet_dns"),
                rule_conditions=[
                    LogsourceCondition(category="dns"),
                    RuleContainsFieldCondition("query")
                ]
            ),
            ProcessingItem(
                identifier="tracee_dns_request_fieldmapping",
                transformation=FieldMappingTransformation({
                    "query": "dstHostname"
                }),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("tracee_dns_request_logsourcemapping"),
                    RuleContainsFieldCondition("query")
                ]
            ),
            ProcessingItem(
                identifier="tracee_dns_answer_logsourcemapping",
                transformation=ChangeLogsourceTransformation("tracee", product="net_packet_dns_response"),
                rule_conditions=[
                    LogsourceCondition(category="dns"),
                    RuleContainsFieldCondition("answer")
                ]
            ),
            ProcessingItem(
                identifier="tracee_dns_answer_txt_remove_field",
                transformation=RemoveFieldTransformation(["record_type"]),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("tracee_dns_answer_logsourcemapping"),
                    RuleContainsFieldCondition("answer"),
                    RuleContainsDetectionItemCondition("record_type","TXT")
                ],
                field_name_conditions=[
                    IncludeFieldCondition(fields = [".*"], type="re")
                ],
            ),
            ProcessingItem(
                identifier="tracee_dns_answer_txt_field_mapping",
                transformation=FieldMappingTransformation({
                    "answer": "txtAnswer"
                }),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("tracee_dns_answer_txt_remove_field")
                ]
            ),
            ### HTTP
            ProcessingItem(
                identifier="tracee_http_response_logsourcemapping",
                transformation=ChangeLogsourceTransformation("tracee", product="net_packet_http_response"),
                rule_conditions=[
                    LogsourceCondition(category="proxy"),
                    RuleContainsFieldCondition("sc-status")
                ]
            ),
            ProcessingItem(
                identifier="tracee_http_response_logsourcemapping2",
                transformation=ChangeLogsourceTransformation("tracee", product="net_packet_http_response"),
                rule_conditions=[
                    LogsourceCondition(category="webserver"),
                    RuleContainsFieldCondition("sc-status")
                ]
            ),
            ProcessingItem(
                identifier="tracee_http_request_logsourcemapping",
                transformation=ChangeLogsourceTransformation("tracee", product="net_packet_http_request"),
                rule_conditions=[
                    LogsourceCondition(category="proxy"),
                    LogsourceCondition(category="webserver")
                ],
                rule_condition_linking=any
            ),
            ProcessingItem(
                identifier="tracee_http_uri_extensio_mapping",
                transformation=ReplaceStringTransformation(r'^', r'*'),
                field_name_conditions=[
                    IncludeFieldCondition(fields=["c-uri-extension"], type="re"),
                ],
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("tracee_http_request_logsourcemapping")
                ]
            ),
            ProcessingItem(
                identifier="tracee_http_fieldmapping",
                transformation=FieldMappingTransformation({
                    "c-useragent": "httpUserAgent",
                    "cs-user-agent": "httpUserAgent",
                    "c-uri": "httpUri",
                    "cs-uri": "httpUri",
                    "cs-method": "httpMethod",
                    "cs-host":"httpHost",
                    "sc-status":"httpStatusCode",
                    "c-uri-extension":"httpUri",
                    "c-uri-query":"httpUri",
                    "cs-uri-query":"httpUri",
                    "cs-uri-stem":"httpUri",
                    "cs-cookie":"httpCookie",
                    "dst_ip":"dstIP",
                    "cs-referer": "httpReferer",
                }),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("tracee_http_response_logsourcemapping"),
                    RuleProcessingItemAppliedCondition("tracee_http_request_logsourcemapping")
                ],
                rule_condition_linking=any
            ),


            ### Process Creation
            ProcessingItem(
                identifier="tracee_process_creation_logsourcemapping",
                transformation=ChangeLogsourceTransformation("tracee", product="sched_process_exec"),
                rule_conditions=[
                    LogsourceCondition(product="linux", category="process_creation"),
                ]
            ),
            ProcessingItem(
                identifier="tracee_process_creation_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Image": "cmdpath",
                }),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("tracee_process_creation_logsourcemapping")
                ]
            ),
            ProcessingItem(
                identifier="tracee_generic_fieldmapping",
                transformation=FieldMappingTransformation({
                    "TargetFilename": "file_path",
                    "Image": "eventObj.ProcessName",
                    "DestinationIp": "dst",
                    "DestinationHostname": "dstHostname",
                    "SourceIp": "src",
                    "CommandLine": "argv",
                })
            ),
            ProcessingItem(
                identifier="tracee_fix_image_field",
                transformation=ReplaceStringTransformation(r'(\.?\*?).*?([^/]+)$',r'\g<1>\g<2>'),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("tracee_generic_fieldmapping")
                ],
                field_name_conditions=[
                    IncludeFieldCondition(fields=["eventObj.ProcessName"], type="re"),
                ]
            ),
            ProcessingItem(
                identifier="tracee_skip_rules_unsupported_fields",
                transformation=RuleFailureTransformation("Fields in Rule not supported"),
                rule_conditions=[
                    RuleContainsFieldCondition("User"),
                    RuleContainsFieldCondition("ParentImage"),
                    RuleContainsFieldCondition("ParentCommandLine"),
                    RuleContainsFieldCondition("LogonId"),
                    RuleContainsFieldCondition("CurrentDirectory"),
                ],
                rule_condition_linking=any
            ),

            # Handle unsupported log sources - here we are checking whether none of the log source-specific transformations
            # that were set above have applied and throwing a RuleFailureTransformation error if this condition is met. Otherwise,
            # a separate processing item would be needed for every unsupported log source type
            ProcessingItem(
                identifier="tracee_fail_rule_not_supported",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation(
                    "Rule type not yet supported by the Tracee Sigma backend!"),
                rule_condition_negation=True,
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("tracee_generic_file_event_logsourcemapping"),
                    RuleProcessingItemAppliedCondition("tracee_process_creation_logsourcemapping"),
                    RuleProcessingItemAppliedCondition("tracee_network_connection_ipv4_logsourcemapping"),
                    RuleProcessingItemAppliedCondition("tracee_network_connection_tcp_logsourcemapping"),
                    RuleProcessingItemAppliedCondition("tracee_network_connection_dns_logsourcemapping"),
                    RuleProcessingItemAppliedCondition("tracee_dns_request_logsourcemapping"),
                    #RuleProcessingItemAppliedCondition("tracee_dns_answer_logsourcemapping"),
                    RuleProcessingItemAppliedCondition("tracee_http_request_logsourcemapping"),
                    RuleProcessingItemAppliedCondition("tracee_http_request_logsourcemapping2"),
                    RuleProcessingItemAppliedCondition("tracee_http_response_logsourcemapping")
                ],
            ),

            # Handle rules that use aggregate functions
            ProcessingItem(
                identifier="tracee_fail_rule_conditions_not_supported",
                transformation=RuleFailureTransformation(
                    "Rules with aggregate function conditions like count, min, max, avg, sum, and near are not supported by the Tracee Sigma backend!"),
                rule_conditions=[
                    AggregateRuleProcessingCondition()
                ],
            ),
        ]
    )