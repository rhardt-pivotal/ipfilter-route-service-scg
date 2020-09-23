package io.pivotal.quickhitgateway;

import io.netty.handler.ipfilter.IpFilterRuleType;
import io.netty.handler.ipfilter.IpSubnetFilterRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.filter.factory.SetStatusGatewayFilterFactory;
import org.springframework.cloud.gateway.handler.AsyncPredicate;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Meant to be used as a route service that can be bound to a CF route.  It will check the
 * X-Forwarded-For header values against an accept list and a reject list
 * (spring property: bad.source.ips and good.source.ips)
 * They should each be a comma-separated list of CIDRs, e.g.
 * 10.20.30.0/24,209.171.0.0/16
 * If the source is on the blacklist, it will return a 503, otherwise it will
 * proxy (incl. all headers, paths, query strings) to whatever is in the
 * X-CF-Forwarded-Url header.  It will also send some other headers to tell
 * gorouter not to send the request back through this route service.
 */
@SpringBootApplication
@RestController
public class QuickHitGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(QuickHitGatewayApplication.class, args);
	}

	private static final Logger log = LoggerFactory.getLogger(QuickHitGatewayApplication.class.getName());


	private List<IpSubnetFilterRule> convert(List<String> values) {
		log.debug("*** CONVERT");
		List<IpSubnetFilterRule> sources = new ArrayList<>();
		for (String arg : values) {
			addSource(sources, arg);
		}
		return sources;
	}

	private void addSource(List<IpSubnetFilterRule> sources, String source) {
		log.debug("ADDING - "+source);
		if (!source.contains("/")) { // no netmask, add default
			source = source + "/32";
		}

		String[] ipAddressCidrPrefix = source.split("/",2);
		String ipAddress = ipAddressCidrPrefix[0];
		int cidrPrefix = Integer.parseInt(ipAddressCidrPrefix[1]);
		IpSubnetFilterRule r = new IpSubnetFilterRule(ipAddress, cidrPrefix, IpFilterRuleType.ACCEPT);
		log.info("Rule: "+r);
		sources.add(r);
	}


	@Value("${accept.source.ips:255.255.255.255}")
	String goodSources;

	@Value("${deny.source.ips:255.255.255.255}")
	String badSources;

	@Value("${deny.url.paths:%%%%%%%%}")
	String rejectPaths;

	private static final String MATCH_ALL_PATHS = "%%%MATCH_ALL_PATHS%%%";
	private static final String X_CF_FORWARDED_URL = "X-Cf-Forwarded-Url";


	private static final String ROUTE_SERVICE_ALLOW = "ROUTE_SERVICE_ALLOW";
	private static final String ROUTE_SERVICE_REJECT = "ROUTE_SERVICE_REJECT";


	private List<IpSubnetFilterRule> goodIpRules;
	private List<IpSubnetFilterRule> badIpRules;
	private List<String> rejectPathStrings;

	@PostConstruct
	private void buildSources() {
		goodIpRules = convert(Arrays.asList(goodSources.split(",")));
		badIpRules = convert(Arrays.asList(badSources.split(",")));
		rejectPathStrings = Arrays.asList(rejectPaths.split(",")).stream().map(String::trim).collect(Collectors.toList());
	}


	public AsyncPredicate<ServerWebExchange> apply() {

		return exchange -> {

			//exchange.getRequest().getHeaders().forEach((k,v) -> log.debug("Header: {}  ->  {}", k, v));

			List<String> xffs = exchange.getRequest().getHeaders().get("X-Forwarded-For");
			if (xffs == null || xffs.size() == 0) {
				log.warn("{}  No X-Forwarded-For header, rejecting", ROUTE_SERVICE_REJECT);
				return Mono.just(false);
			}
			if (xffs.get(0).contains(",")){
				String xffStr = xffs.get(0);
				xffs = Arrays.asList(xffStr.split(",")).stream().map(s -> s.trim()).collect(Collectors.toList());
			}

			List<String> xcffu =  exchange.getRequest().getHeaders().get(X_CF_FORWARDED_URL);
			if (xcffu == null || xcffu.size() == 0) {
				log.warn("{}  No X-CF-Forwarded-URL header, rejecting", ROUTE_SERVICE_REJECT);
				return Mono.just(false);
			}
			String xcfString = xcffu.get(0);
			String requestPath = null;
			try {
				requestPath = new URI(xcfString).getPath();
				String[] rpArr = requestPath.split("\\/");
				if (rpArr.length > 0) {
					requestPath = rpArr[1];
				}
				else {
					requestPath = "";
				}
			}
			catch (URISyntaxException u) {
				u.printStackTrace();
				return Mono.just(false);
			}


			for (String xff : xffs) {
				InetSocketAddress isa = new InetSocketAddress(xff, 0);
				log.debug("Checking: "+isa);
				for (IpSubnetFilterRule rule : goodIpRules) {
					log.debug("Checking "+isa.getHostString()+" against good rule: "+rule);
					if (rule.matches(isa)){
						log.info("{}  MATCHED A GOOD IP: passing through",  ROUTE_SERVICE_ALLOW);
						return Mono.just(true);
					}
				}
				for (IpSubnetFilterRule rule : badIpRules) {
					log.debug("Checking "+isa.getHostString()+" against bad rule: "+rule);
					if (rule.matches(isa)){
						log.debug("MATCHED A BAD IP: checking path against paths to deny");
						log.debug("PATH: {}", requestPath);
						for (String mString : rejectPathStrings) {
							if (mString.equalsIgnoreCase(MATCH_ALL_PATHS)) {
								log.debug("found: "+MATCH_ALL_PATHS+" immediately rejecting");
								log.warn("{}  Matched reject IP {} and {}", ROUTE_SERVICE_REJECT, isa.toString(), MATCH_ALL_PATHS);
								return Mono.just(false);
							}
							else if (requestPath.equalsIgnoreCase(mString)) {
								log.debug("PATH SEGMENT {} matched string: {} - immediately rejecting", requestPath, mString);
								log.warn("{}  Matched Reject IP {} and Path: {}", ROUTE_SERVICE_REJECT, isa.toString(), mString);
								return Mono.just(false);
							}
						}
						// if we get to this point, no matter how many reject ips match, they'll never match a reject path, so we allow the request through
						log.debug("Matched a reject-IP but no reject-path, so letting the request through");
						log.info("{}  Matched reject IP {} but no reject path matched {}", ROUTE_SERVICE_ALLOW, isa.toString(), requestPath);
						return Mono.just(true);
					}
				}

			}
			log.info("{}  NO EXPLICIT MATCH FOR {} - default is to pass through", ROUTE_SERVICE_ALLOW, xffs);
			return Mono.just(true);
		};
	}


	@Bean
	public RouteLocator customRouteLocator(RouteLocatorBuilder builder,
										   SetStatusGatewayFilterFactory ssgf) {

		//@formatter:off
		return builder.routes()
				//x-forwarded-for in the good range, send on to the intended destination
				.route("good_route", r -> r.asyncPredicate(apply())
						.filters(f -> f.requestHeaderToRequestUri("X-CF-Forwarded-Url")).uri("no://op"))
				//otherwise, send a 401,
				.route("default_bad_route", r -> r.alwaysTrue()
						.filters(f -> f.filter(ssgf.apply(c -> c.setStatus("SERVICE_UNAVAILABLE"))))
						.uri("no://op"))
				.build();
		//@formatter:on
	}



}

