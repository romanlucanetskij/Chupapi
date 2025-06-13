package com.example.courseworkLuchnetskyi.mapper;

import com.example.courseworkLuchnetskyi.dto.request.MatchRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.MatchResponseDto;
import com.example.courseworkLuchnetskyi.model.Match;
import org.mapstruct.*;

@Mapper(componentModel = "spring")
public interface MatchMapper {

    @Mapping(target = "teamA", ignore = true)
    @Mapping(target = "teamB", ignore = true)
    @Mapping(target = "tournament", ignore = true)
    Match toEntity(MatchRequestDto dto);

    MatchResponseDto toDto(Match match);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateFromDto(@MappingTarget Match match, MatchRequestDto dto);

}
