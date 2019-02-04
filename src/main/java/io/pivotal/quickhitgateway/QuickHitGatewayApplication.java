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
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Meant to be used as a route service that can be bound to a CF route.  It will check the
 * X-Forwarded-For header values against a black list (spring property: bad.source.ips)
 * The blacklist should be a comma-separated list of CIDRs, e.g.
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


	@Value("${bad.source.ips:255.255.255.255}")
	String badSources;


	public AsyncPredicate<ServerWebExchange> apply(String badSources) {
		List<IpSubnetFilterRule> sources = convert(Arrays.asList(badSources.split(",")));
		log.debug("** SOURCES: "+sources);

		return exchange -> {
			List<String> xffs = exchange.getRequest().getHeaders().get("X-Forwarded-For");
			if (xffs == null || xffs.size() == 0) {
				return Mono.just(false);
			}
			if (xffs.get(0).contains(",")){
				String xffStr = xffs.get(0);
				xffs = Arrays.asList(xffStr.split(",")).stream().map(s -> s.trim()).collect(Collectors.toList());
			}
			for (String xff : xffs) {
				InetSocketAddress isa = new InetSocketAddress(xff, 0);
				log.debug("Checking: "+isa);
				for (IpSubnetFilterRule rule : sources) {
					log.debug("Checking "+isa.getHostString()+" against "+rule);
					if (rule.matches(isa)){
						log.debug("MATCHES");
						return Mono.just(true);
					}
				}
			}
			log.debug("NO MATCH");
			return Mono.just(false);
		};
	}


	@Bean
	public RouteLocator customRouteLocator(RouteLocatorBuilder builder,
										   SetStatusGatewayFilterFactory ssgf) {

		//@formatter:off
		return builder.routes()
				//x-forwarded-for in the bad range, send a 401
				.route("bad_route", r -> r.asyncPredicate(apply(badSources))
						.filters(f -> f.filter(ssgf.apply(c -> c.setStatus("SERVICE_UNAVAILABLE"))))
						.uri("no://op"))
				//otherwise, there should be a x-cf-forwarded-url header,
				// send it there.  If it's not there, this isn't be used as a route-service
				.route("good_route", r -> r.alwaysTrue()
						.filters(f -> f.requestHeaderToRequestUri("X-CF-Forwarded-Url")).uri("no://op"))
				.build();
		//@formatter:on
	}



}

