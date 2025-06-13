package com.example.courseworkLuchnetskyi.mapper;

import com.example.courseworkLuchnetskyi.dto.request.PlayerRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.PlayerResponseDto;
import com.example.courseworkLuchnetskyi.model.Player;
import org.mapstruct.*;

@Mapper(componentModel = "spring")
public interface PlayerMapper {

    @Mapping(target = "team", ignore = true)
    Player toEntity(PlayerRequestDto dto);

    PlayerResponseDto toDto(Player player);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updatePlayerFromDto(@MappingTarget Player player, PlayerRequestDto dto);
}
